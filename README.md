# gh-sec-overview

A single-file Python CLI that gives you a consolidated security overview
across all GitHub repositories you personally own. It is essentially the
org-level Security Overview dashboard, but for a personal account.

GitHub exposes no user-level aggregate endpoint for security alerts, so the
tool enumerates every repo you own and queries the Dependabot, code-scanning,
and secret-scanning alert endpoints per repo (concurrently), then rolls the
results up into a single terminal view.

## Requirements

- Python 3 (standard library only, no pip installs).
- The GitHub CLI (`gh`) installed and authenticated. Install it from
  https://cli.github.com/ and run `gh auth login` once.

All authentication and API access go through `gh`. The script never handles
tokens directly.

## Usage

```
./gh-sec-overview.py
# or
python3 gh-sec-overview.py
```

On startup the script verifies that `gh` is on your PATH and that
`gh auth status` succeeds. If either check fails it prints a clear message and
exits non-zero.

### What it does

1. Lists all repos owned by the authenticated user.
2. For each repo, fetches open alerts from three endpoints (Dependabot,
   code scanning, secret scanning), running repos concurrently.
3. Handles per-call errors gracefully. A feature that is disabled for a repo
   (typically a 403 or 404) is marked off / N/A and skipped rather than
   crashing the run. Only genuinely unexpected errors are surfaced.
4. Prints a summary header, one section per repo that has alerts (sorted so the
   most severe repos come first), and a per-repo summary table at the bottom.

### Flags

```
--show-clean   Also list repos that have no alerts.
--summary      Print only the per-repo summary table.
--severity {critical,high,medium,low}
               Only show alerts at or above this severity. Default is low,
               which shows everything.
--json         Dump the aggregated raw data as JSON instead of the pretty view.
--no-color     Disable ANSI color and clickable hyperlinks.
-h, --help     Show usage.
```

### Examples

```
./gh-sec-overview.py
./gh-sec-overview.py --show-clean
./gh-sec-overview.py --severity high
./gh-sec-overview.py --summary
./gh-sec-overview.py --json > alerts.json
```

## Output

By default the tool prints a clean terminal view:

- A summary header with total open alerts broken down by type
  (Dependabot, code scanning, secret scanning) and by severity
  (critical, high, medium, low).
- One section per repo that has alerts, with color-coded severity, the alert
  type, a short label, and a link to each alert. In a supporting terminal the
  label text is a clickable hyperlink (OSC 8); otherwise the raw URL is shown.
- A per-repo summary table mapping each repo to its total open alerts and a
  per-severity breakdown.

Color and hyperlinks are used only when stdout is an interactive terminal.
The script respects the `NO_COLOR` environment variable and the `--no-color`
flag, and falls back to plain text when output is piped or redirected.

Secret-scanning alerts have no severity field, so they are treated as their own
top-priority category and sorted to the top.
