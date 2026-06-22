#!/usr/bin/env python3
"""
gh-sec-overview.py

A consolidated security overview across all GitHub repos owned by the
authenticated user -- essentially the org-level "Security Overview" dashboard,
but for a personal account.

GitHub exposes no user-level aggregate endpoint for security alerts, so this
tool enumerates every repo you own and queries the Dependabot, code-scanning,
and secret-scanning alert endpoints per repo (concurrently), then rolls the
results up into a single terminal view.

Everything goes through the `gh` CLI for auth and API access -- no tokens are
handled here directly. stdlib only; no pip installs required.

Usage:
    ./gh-sec-overview.py
    python3 gh-sec-overview.py --show-clean
    ./gh-sec-overview.py --severity high
    ./gh-sec-overview.py --json
"""

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of repos queried in parallel. Each repo is 3 serial-ish gh calls, so
# this is really ~8 concurrent gh invocations.
MAX_WORKERS = 8

# Severity ordering, highest first. Used for sorting and for the --severity
# minimum-severity filter. Secret scanning has no severity; we treat its hits
# as their own top-priority category (see SECRET_SORT_RANK below).
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}

# Alert "type" labels used throughout.
TYPE_DEPENDABOT = "dependabot"
TYPE_CODE = "code-scanning"
TYPE_SECRET = "secret-scanning"

# ANSI color codes keyed by severity, plus a couple of helpers.
ANSI = {
    "critical": "\033[1;37;41m",   # bold white on red
    "high": "\033[1;31m",          # bold red
    "medium": "\033[1;33m",        # bold yellow
    "low": "\033[0;36m",           # cyan
    "secret": "\033[1;35m",        # bold magenta (secret scanning)
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


# ---------------------------------------------------------------------------
# Output styling helpers (TTY / NO_COLOR / OSC 8 aware)
# ---------------------------------------------------------------------------

class Style:
    """Encapsulates color + hyperlink behavior based on TTY and flags."""

    def __init__(self, use_color, use_links):
        self.use_color = use_color
        self.use_links = use_links

    def color(self, text, key):
        """Wrap text in an ANSI color if coloring is enabled."""
        if not self.use_color or key not in ANSI:
            return text
        return f"{ANSI[key]}{text}{ANSI['reset']}"

    def link(self, text, url):
        """
        Render an OSC 8 terminal hyperlink so `text` is clickable.

        Falls back to "text (url)" when hyperlinks are disabled (e.g. piping
        to a file or NO_COLOR / --no-color).
        """
        if not self.use_links:
            # When not interactive, make the raw URL visible and greppable.
            if text == url:
                return url
            return f"{text} ({url})"
        return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


# ---------------------------------------------------------------------------
# gh CLI plumbing
# ---------------------------------------------------------------------------

def run_gh(args, check=True):
    """
    Run a `gh` command and return (returncode, stdout, stderr).

    `args` is the list of arguments after `gh`. When check=False we never
    raise; the caller inspects the return code (used for per-alert-endpoint
    calls that are expected to fail when a feature is disabled).
    """
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"`gh {' '.join(args)}` failed (exit {proc.returncode}):\n"
            f"{proc.stderr.strip()}"
        )
    return proc.returncode, proc.stdout, proc.stderr


def preflight():
    """
    Verify `gh` is installed and authenticated. Exit non-zero with a clear
    message otherwise.
    """
    if shutil.which("gh") is None:
        sys.stderr.write(
            "error: the GitHub CLI `gh` was not found on your PATH.\n"
            "Install it from https://cli.github.com/ and run `gh auth login`.\n"
        )
        sys.exit(2)

    # `gh auth status` exits non-zero when not logged in.
    proc = subprocess.run(
        ["gh", "auth", "status"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.stderr.write(
            "error: `gh` is installed but you are not authenticated.\n"
            "Run `gh auth login` and try again.\n\n"
            f"{proc.stderr.strip()}\n"
        )
        sys.exit(2)


# ---------------------------------------------------------------------------
# Data fetching
# ---------------------------------------------------------------------------

def list_owned_repos():
    """
    Return a list of repos owned by the authenticated user.

    Each item is a dict with: full_name, owner, name, visibility, archived.
    """
    _, stdout, _ = run_gh([
        "api", "user/repos", "--paginate", "-X", "GET",
        "-f", "affiliation=owner", "-f", "per_page=100",
    ])

    # --paginate concatenates JSON arrays as separate top-level documents in
    # some gh versions, but for `gh api --paginate` of a single array endpoint
    # it returns one combined JSON array. Be defensive and handle both.
    repos = _parse_paginated_json(stdout)

    result = []
    for r in repos:
        owner = (r.get("owner") or {}).get("login", "")
        result.append({
            "full_name": r.get("full_name", ""),
            "owner": owner,
            "name": r.get("name", ""),
            "visibility": r.get("visibility", "private" if r.get("private") else "public"),
            "archived": bool(r.get("archived", False)),
        })
    return result


def _parse_paginated_json(stdout):
    """
    Parse output from `gh api --paginate`. Normally a single JSON array, but
    handle concatenated arrays/objects defensively by using raw_decode.
    """
    stdout = stdout.strip()
    if not stdout:
        return []

    # Fast path: a single well-formed JSON document.
    try:
        data = json.loads(stdout)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass

    # Slow path: multiple concatenated JSON documents.
    items = []
    decoder = json.JSONDecoder()
    idx = 0
    n = len(stdout)
    while idx < n:
        while idx < n and stdout[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(stdout, idx)
        if isinstance(obj, list):
            items.extend(obj)
        else:
            items.append(obj)
        idx = end
    return items


def fetch_alerts(repo, endpoint):
    """
    Fetch open alerts for `repo` from a given alert endpoint path suffix.

    Returns a tuple (status, data):
      status == "ok"  -> data is a list of raw alert dicts (possibly empty)
      status == "off" -> feature disabled / not available (403/404); data=[]
      status == "err" -> genuinely unexpected error; data is the stderr string

    We never raise here; per-call resilience is the whole point.
    """
    path = f"repos/{repo['owner']}/{repo['name']}/{endpoint}"
    rc, stdout, stderr = run_gh(
        ["api", "--paginate", path], check=False
    )

    if rc == 0:
        try:
            return "ok", _parse_paginated_json(stdout)
        except json.JSONDecodeError:
            return "err", f"could not parse JSON from {path}"

    # Classify the failure. 403/404 (and "disabled"/"not enabled" messages)
    # mean the feature is off or there's nothing to see -- expected, not fatal.
    blob = (stderr or "").lower()
    expected_markers = (
        "403", "404", "not found", "disabled", "not enabled",
        "no analysis", "advanced security", "must enable",
        "secret scanning is disabled", "code scanning is not enabled",
    )
    if any(m in blob for m in expected_markers):
        return "off", []

    return "err", stderr.strip()


def normalize_dependabot(alert):
    """Extract the fields we care about from a Dependabot alert."""
    adv = alert.get("security_advisory") or {}
    dep = alert.get("dependency") or {}
    pkg = (dep.get("package") or {}).get("name", "?")
    ghsa = adv.get("ghsa_id") or ""
    cve = adv.get("cve_id") or ""
    ident = cve or ghsa or "?"
    severity = (adv.get("severity") or "low").lower()
    if severity not in SEVERITY_RANK:
        severity = "low"
    summary = adv.get("summary") or ""
    label = f"{pkg}: {summary}" if summary else pkg
    return {
        "type": TYPE_DEPENDABOT,
        "severity": severity,
        "label": label,
        "ident": ident,
        "url": alert.get("html_url", ""),
    }


def normalize_code_scanning(alert):
    """Extract the fields we care about from a code-scanning alert."""
    rule = alert.get("rule") or {}
    severity = (rule.get("security_severity_level")
                or rule.get("severity") or "low").lower()
    # Code-scanning rule.severity can be "warning"/"error"/"note"; map those.
    sev_map = {"error": "high", "warning": "medium", "note": "low"}
    severity = sev_map.get(severity, severity)
    if severity not in SEVERITY_RANK:
        severity = "low"
    label = rule.get("description") or rule.get("name") or rule.get("id") or "code-scanning alert"
    return {
        "type": TYPE_CODE,
        "severity": severity,
        "label": label,
        "ident": rule.get("id") or "",
        "url": alert.get("html_url", ""),
    }


def normalize_secret_scanning(alert):
    """
    Extract fields from a secret-scanning alert. These have no severity; we
    treat the whole category as top-priority.
    """
    label = (alert.get("secret_type_display_name")
             or alert.get("secret_type") or "secret")
    return {
        "type": TYPE_SECRET,
        "severity": "critical",  # surface secrets as top priority
        "label": label,
        "ident": alert.get("secret_type") or "",
        "url": alert.get("html_url", ""),
    }


def gather_repo(repo):
    """
    Fetch and normalize all alerts for one repo across the three endpoints.

    Returns a dict describing the repo, its alerts, and per-feature status.
    """
    endpoints = [
        (TYPE_DEPENDABOT,
         "dependabot/alerts?state=open&per_page=100",
         normalize_dependabot),
        (TYPE_CODE,
         "code-scanning/alerts?state=open&per_page=100",
         normalize_code_scanning),
        (TYPE_SECRET,
         "secret-scanning/alerts?state=open&per_page=100",
         normalize_secret_scanning),
    ]

    alerts = []
    feature_status = {}
    errors = []

    for type_name, endpoint, normalizer in endpoints:
        status, data = fetch_alerts(repo, endpoint)
        feature_status[type_name] = status
        if status == "ok":
            for raw in data:
                alerts.append(normalizer(raw))
        elif status == "err":
            errors.append((type_name, data))

    return {
        "repo": repo,
        "alerts": alerts,
        "feature_status": feature_status,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Aggregation / sorting
# ---------------------------------------------------------------------------

def severity_at_least(severity, minimum):
    """True if `severity` is at least as severe as `minimum`."""
    return SEVERITY_RANK.get(severity, 99) <= SEVERITY_RANK.get(minimum, 99)


def summarize(results):
    """
    Build aggregate counts across all repos.

    Returns dict with by_type and by_severity counters plus the grand total.
    """
    by_type = {TYPE_DEPENDABOT: 0, TYPE_CODE: 0, TYPE_SECRET: 0}
    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    total = 0
    for res in results:
        for alert in res["alerts"]:
            by_type[alert["type"]] = by_type.get(alert["type"], 0) + 1
            by_severity[alert["severity"]] = by_severity.get(alert["severity"], 0) + 1
            total += 1
    return {"by_type": by_type, "by_severity": by_severity, "total": total}


def repo_sort_key(res):
    """
    Sort repos so the scariest come first: by count of each severity tier,
    highest tier first, then by total alert count.
    """
    counts = [0] * len(SEVERITY_ORDER)
    for alert in res["alerts"]:
        counts[SEVERITY_RANK[alert["severity"]]] += 1
    # Negative so that "more" sorts first.
    return (*[-c for c in counts], -len(res["alerts"]))


def alert_sort_key(alert):
    """Within a repo, most severe first; secrets float up via critical rank."""
    return (SEVERITY_RANK.get(alert["severity"], 99), alert["type"], alert["label"])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

TYPE_TAG = {
    TYPE_DEPENDABOT: "DEP",
    TYPE_CODE: "COD",
    TYPE_SECRET: "SEC",
}


def render_summary(style, summary, repo_count, scanned_count):
    """Print the top-level summary header."""
    lines = []
    title = "GitHub Security Overview"
    lines.append(style.color(title, "bold"))
    lines.append(style.color("=" * len(title), "dim"))

    total = summary["total"]
    lines.append(
        f"Scanned {scanned_count} of {repo_count} owned repos -- "
        f"{style.color(str(total), 'bold')} open alerts"
    )

    bt = summary["by_type"]
    lines.append(
        "  by type: "
        f"Dependabot {bt[TYPE_DEPENDABOT]}  |  "
        f"code scanning {bt[TYPE_CODE]}  |  "
        f"secret scanning {bt[TYPE_SECRET]}"
    )

    bs = summary["by_severity"]
    sev_parts = []
    for sev in SEVERITY_ORDER:
        label = f"{sev} {bs[sev]}"
        sev_parts.append(style.color(label, sev) if bs[sev] else style.color(label, "dim"))
    lines.append("  by severity: " + "  ".join(sev_parts))

    print("\n".join(lines))
    print()


def render_repo(style, res, term_width, min_severity):
    """Print one repo section with its alerts. Returns True if anything printed."""
    repo = res["repo"]

    # Apply severity filter to this repo's alerts.
    alerts = [a for a in res["alerts"]
              if severity_at_least(a["severity"], min_severity)]
    if not alerts:
        return False

    alerts.sort(key=alert_sort_key)

    # Repo header line with visibility / archived annotations.
    annotations = [repo["visibility"]]
    if repo["archived"]:
        annotations.append("archived")
    header = f"{repo['full_name']}  ({', '.join(annotations)})  [{len(alerts)} alerts]"
    print(style.color(header, "bold"))

    # Compute column widths. Layout:  SEV  TYPE  label
    sev_col = max(len(s) for s in SEVERITY_ORDER)  # width for severity word
    type_col = 3  # DEP / COD / SEC
    # Remaining width for the label/link text.
    prefix = 2 + sev_col + 2 + type_col + 2  # indent + cols + gaps
    label_width = max(20, term_width - prefix)

    for alert in alerts:
        sev = alert["severity"]
        sev_text = sev.upper().ljust(sev_col)
        # Secret scanning has no real severity; show "SECRET" coloring.
        sev_key = "secret" if alert["type"] == TYPE_SECRET else sev
        sev_render = style.color(sev_text, sev_key)

        type_tag = TYPE_TAG.get(alert["type"], "?").ljust(type_col)

        label = alert["label"].replace("\n", " ").strip()
        ident = alert.get("ident") or ""
        if ident and ident not in label:
            label = f"{label}  [{ident}]"

        # Truncate to fit, leaving room for an ellipsis.
        if len(label) > label_width:
            label = label[: label_width - 1].rstrip() + "…"

        url = alert.get("url") or ""
        text = style.link(label, url) if url else label

        print(f"  {sev_render}  {type_tag}  {text}")

    print()
    return True


def render_offline_notes(style, results):
    """Print a compact note about repos where features were off or errored."""
    err_repos = [r for r in results if r["errors"]]
    if not err_repos:
        return
    print(style.color("Notes (unexpected errors):", "dim"))
    for res in err_repos:
        for type_name, msg in res["errors"]:
            short = msg.splitlines()[0] if msg else "unknown error"
            print(style.color(f"  ! {res['repo']['full_name']} [{type_name}]: {short}", "dim"))
    print()


def severity_counts(res):
    """Return a per-severity count dict for one repo's alerts, plus total."""
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for alert in res["alerts"]:
        counts[alert["severity"]] += 1
    counts["total"] = len(res["alerts"])
    return counts


def render_table(style, results, min_severity, show_clean):
    """
    Print a per-repo summary table: repo -> total open alerts, broken down by
    severity. Sorted scariest-first. Respects --severity (filters which alerts
    are counted) and --show-clean (whether zero-alert repos appear).
    """
    # Build rows, applying the severity filter to the counts.
    rows = []
    for res in results:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        total = 0
        for alert in res["alerts"]:
            if not severity_at_least(alert["severity"], min_severity):
                continue
            counts[alert["severity"]] += 1
            total += 1
        if total == 0 and not show_clean:
            continue
        rows.append((res["repo"], counts, total))

    if not rows:
        print(style.color("No repos to summarize.", "dim"))
        return

    # Sort scariest-first using the same tiered logic as repo_sort_key.
    def key(row):
        _, counts, total = row
        return (*[-counts[sev] for sev in SEVERITY_ORDER], -total)
    rows.sort(key=key)

    # Column widths.
    repo_w = max(len("REPOSITORY"), max(len(r[0]["full_name"]) for r in rows))
    repo_w = min(repo_w, 50)  # cap so the table stays readable
    num_w = 5

    # Header.
    headers = ["REPOSITORY".ljust(repo_w), "TOTAL".rjust(num_w)]
    headers += [sev[:4].upper().rjust(num_w) for sev in SEVERITY_ORDER]
    header_line = "  ".join(headers)
    print(style.color(header_line, "bold"))
    print(style.color("-" * len(header_line), "dim"))

    # Rows.
    for repo, counts, total in rows:
        name = repo["full_name"]
        if len(name) > repo_w:
            name = name[: repo_w - 1] + "…"
        cells = [name.ljust(repo_w), style.color(str(total).rjust(num_w), "bold")]
        for sev in SEVERITY_ORDER:
            n = counts[sev]
            cell = str(n).rjust(num_w)
            cells.append(style.color(cell, sev) if n else style.color(cell, "dim"))
        print("  ".join(cells))
    print()


def build_json_payload(results, summary):
    """Assemble the aggregated raw data structure for --json output."""
    repos = []
    for res in results:
        repos.append({
            "full_name": res["repo"]["full_name"],
            "owner": res["repo"]["owner"],
            "name": res["repo"]["name"],
            "visibility": res["repo"]["visibility"],
            "archived": res["repo"]["archived"],
            "feature_status": res["feature_status"],
            "alerts": res["alerts"],
            "errors": [
                {"type": t, "message": m} for t, m in res["errors"]
            ],
        })
    return {
        "summary": summary,
        "repos": repos,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="gh-sec-overview.py",
        description=(
            "Consolidated security overview (Dependabot, code scanning, "
            "secret scanning) across all GitHub repos you own. Uses the `gh` "
            "CLI for auth and API access."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ./gh-sec-overview.py\n"
            "  ./gh-sec-overview.py --show-clean\n"
            "  ./gh-sec-overview.py --severity high\n"
            "  ./gh-sec-overview.py --summary\n"
            "  ./gh-sec-overview.py --json > alerts.json\n"
        ),
    )
    parser.add_argument(
        "--show-clean", action="store_true",
        help="also list repos that have no alerts",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="only print the per-repo summary table (repo -> alert counts)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable ANSI color and clickable hyperlinks",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="dump aggregated raw data as JSON instead of the pretty view",
    )
    parser.add_argument(
        "--severity", choices=SEVERITY_ORDER, default="low",
        help="only show alerts at or above this severity (default: low = all)",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    preflight()

    # Decide on styling. JSON mode is always plain.
    is_tty = sys.stdout.isatty()
    no_color_env = bool(os.environ.get("NO_COLOR"))
    use_color = is_tty and not no_color_env and not args.no_color and not args.json
    use_links = is_tty and not args.json  # OSC 8 only makes sense interactively

    style = Style(use_color=use_color, use_links=use_links)

    # 1. Enumerate owned repos.
    try:
        repos = list_owned_repos()
    except RuntimeError as e:
        sys.stderr.write(f"error: could not list repos: {e}\n")
        return 1

    if not repos:
        print("No repos owned by the authenticated user were found.")
        return 0

    # 2 + 3. Fetch alerts per repo, concurrently.
    if not args.json and is_tty:
        sys.stderr.write(
            f"Scanning {len(repos)} repos for open security alerts...\n"
        )
        sys.stderr.flush()

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_to_repo = {ex.submit(gather_repo, r): r for r in repos}
        for future in concurrent.futures.as_completed(future_to_repo):
            try:
                results.append(future.result())
            except Exception as e:  # pragma: no cover - defensive
                repo = future_to_repo[future]
                results.append({
                    "repo": repo,
                    "alerts": [],
                    "feature_status": {},
                    "errors": [("internal", str(e))],
                })

    summary = summarize(results)

    # --json: dump and exit.
    if args.json:
        payload = build_json_payload(results, summary)
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    # Pretty view.
    term_width = shutil.get_terminal_size((100, 24)).columns

    # --summary: print only the per-repo table (plus the header for context).
    if args.summary:
        render_summary(style, summary, len(repos), len(results))
        render_table(style, results, args.severity, args.show_clean)
        render_offline_notes(style, results)
        return 0

    render_summary(style, summary, len(repos), len(results))

    # Sort repos by scariness.
    results_sorted = sorted(results, key=repo_sort_key)

    printed_any = False
    for res in results_sorted:
        has_alerts = bool(res["alerts"])
        if has_alerts:
            if render_repo(style, res, term_width, args.severity):
                printed_any = True
        elif args.show_clean:
            repo = res["repo"]
            # Show clean repos compactly, noting any disabled features.
            off = [t for t, s in res["feature_status"].items() if s == "off"]
            note = f"  ({', '.join(off)} off/N/A)" if off else ""
            print(style.color(f"{repo['full_name']}  -- clean{note}", "dim"))
            printed_any = True

    if not printed_any:
        msg = "No open security alerts"
        if args.severity != "low":
            msg += f" at severity >= {args.severity}"
        msg += ". \U0001f389"
        print(style.color(msg, "low"))

    print()

    # Per-repo summary table at the bottom of the default view.
    if summary["total"] > 0:
        print(style.color("Summary by repo", "bold"))
        render_table(style, results, args.severity, args.show_clean)

    render_offline_notes(style, results)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(130)
