# Getting Started

`rebar3_audit` scans your Erlang/OTP project dependencies against the
[GitHub Advisory Database](https://github.com/advisories) for known
security vulnerabilities in the Hex/Erlang ecosystem.

## Installation

Add `rebar3_audit` to your `project_plugins` in `rebar.config`:

```erlang
{project_plugins, [
    {rebar3_audit, "1.0.0"}
]}.
```

## Basic usage

```bash
rebar3 audit
```

This will:

1. Read your `rebar.lock` to discover Hex dependencies
2. Fetch all Erlang ecosystem advisories from GitHub
3. Match your dependency versions against known vulnerable ranges
4. Report any findings and exit with code 1 if vulnerabilities are found

### Clean output

```
===> Fetching advisories from GitHub Advisory Database...
===> No vulnerabilities found in 8 dependencies. ✓
```

### Vulnerabilities found

```
===> Fetching advisories from GitHub Advisory Database...

╔══════════════════════════════════════════════════════════╗
║  1 vulnerability found in 8 dependencies                ║
╚══════════════════════════════════════════════════════════╝

  🟠 HIGH     jose (1.11.5)
  │ Algorithm confusion in JWT verification
  │ Advisory:   GHSA-9mg4-v392-8j68
  │ Vulnerable: >= 1.0.0, < 1.11.7
  │ Fix:        Upgrade to 1.11.7
  │ URL:        https://github.com/advisories/GHSA-9mg4-v392-8j68
  │
```

## Options

### `--level` — severity threshold

By default, all severities fail the build. Set a higher threshold to allow
lower-severity issues to pass:

```bash
# Only fail on critical vulnerabilities
rebar3 audit --level critical

# Fail on high and critical
rebar3 audit --level high
```

Severity levels (lowest to highest): `low`, `medium`, `high`, `critical`.

### `--format` — output format

```bash
# Human-readable output (default)
rebar3 audit --format human

# JSON output for CI tooling
rebar3 audit --format json
```

The JSON format outputs a single object with `vulnerabilities` (array) and
`dependencies_scanned` (integer). This is used by
[erlang-ci](https://github.com/Taure/erlang-ci) to render PR summary comments.

### `--ignore` — skip specific advisories

If a vulnerability doesn't apply to your usage or you've already mitigated it:

```bash
rebar3 audit --ignore GHSA-xxxx-yyyy-zzzz

# Multiple ignores
rebar3 audit -i GHSA-aaaa-bbbb-cccc -i GHSA-dddd-eeee-ffff
```

### `--token` — GitHub API token

Without a token, you're limited to 60 API requests per hour. With a token,
the limit increases to 5,000:

```bash
rebar3 audit --token ghp_xxxxx

# Or via environment variable (recommended)
export GITHUB_TOKEN=ghp_xxxxx
rebar3 audit
```

In GitHub Actions, `GITHUB_TOKEN` is automatically available.

## Requirements

- **OTP 27+** — uses `json:decode/1` from the standard library
- **rebar.lock** — must exist (run `rebar3 lock` or `rebar3 compile` first)
- **Network access** — fetches advisories from `api.github.com`

## How it works

1. **Lock file parsing** — reads `rebar.lock` and extracts all Hex package
   names and versions (git dependencies are skipped)
2. **Advisory fetch** — queries the GitHub Advisory Database REST API with
   `ecosystem=erlang`, paginating through all results
3. **Version matching** — for each dependency, checks if its version falls
   within any advisory's vulnerable version range using semantic version
   comparison
4. **Severity filtering** — compares matched vulnerability severity against
   the configured `--level` threshold
5. **Reporting** — outputs results in human or JSON format and exits with
   appropriate code
