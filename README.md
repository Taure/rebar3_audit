# rebar3_audit

Audit rebar3 dependencies for known vulnerabilities using the [GitHub Advisory Database](https://github.com/advisories?query=ecosystem%3Aerlang).

The Erlang equivalent of [`mix_audit`](https://github.com/mirego/mix_audit).

## Quick start

Add to your `rebar.config`:

```erlang
{project_plugins, [
    {rebar3_audit, "1.0.0"}
]}.
```

Then run:

```bash
rebar3 audit
```

## Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--token` | `-t` | `GITHUB_TOKEN` env | GitHub token for API access |
| `--level` | `-l` | `low` | Minimum severity to fail on: `critical`, `high`, `medium`, `low` |
| `--format` | `-f` | `human` | Output format: `human` or `json` |
| `--ignore` | `-i` | — | GHSA ID to skip (repeat for multiple) |

```bash
# Only fail on high and critical
rebar3 audit --level high

# JSON output for CI tooling
rebar3 audit --format json

# Ignore specific advisories
rebar3 audit -i GHSA-xxxx-yyyy-zzzz -i GHSA-aaaa-bbbb-cccc
```

## Example output

```
===> Fetching advisories from GitHub Advisory Database...

╔══════════════════════════════════════════════════════════╗
║  2 vulnerabilities found in 12 dependencies             ║
╚══════════════════════════════════════════════════════════╝

  🟠 HIGH     hackney (1.18.0)
  │ Insufficient validation of SSL/TLS certificates
  │ Advisory:   GHSA-9fm9-hp7p-53mf (CVE-2025-1234)
  │ Vulnerable: < 1.24.0
  │ Fix:        Upgrade to 1.24.0
  │ URL:        https://github.com/advisories/GHSA-9fm9-hp7p-53mf
  │

  🟡 MEDIUM   jose (1.11.5)
  │ Algorithm confusion in JWT verification
  │ Advisory:   GHSA-9mg4-v392-8j68
  │ Vulnerable: < 1.11.7
  │ Fix:        Upgrade to 1.11.7
  │ URL:        https://github.com/advisories/GHSA-9mg4-v392-8j68
  │
```

## CI integration

### With erlang-ci (recommended)

```yaml
jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      otp-version: '28'
      enable-audit: true
      audit-level: 'low'        # Fail on all severities (default)
```

This gives you a PR comment with audit results, updated on re-runs.

### Standalone GitHub Action

For repos where you can't modify `rebar.config`:

```yaml
- uses: Taure/rebar3_audit@v1
  with:
    level: 'high'
```

### Custom workflow

```yaml
- name: Audit dependencies
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: rebar3 audit
```

The `GITHUB_TOKEN` increases the API rate limit from 60 to 5,000 requests/hour.

## How it works

1. Reads `rebar.lock` for Hex dependency names and versions
2. Fetches advisories from the [GitHub Advisory Database REST API](https://docs.github.com/en/rest/security-advisories/global-advisories) (Erlang ecosystem)
3. Matches each dependency version against advisory vulnerable ranges
4. Filters by severity threshold (`--level`)
5. Reports findings and exits with code 1 if any match

## Requirements

- **OTP 27+** (uses `json:decode/1`)
- **rebar.lock** must exist (run `rebar3 compile` first)

## Documentation

Full guides available via `rebar3 ex_doc`:

- [Getting Started](guides/getting-started.md) — installation, options, output formats
- [CI Integration](guides/ci-integration.md) — erlang-ci, custom workflows, pre-push hooks
- [GitHub Action](guides/github-action.md) — standalone action for org-wide enforcement
- [Security Workflow](guides/security-workflow.md) — layered security pipeline, triage process, JSON schema

## License

Apache-2.0
