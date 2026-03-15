# Security Workflow

This guide describes how `rebar3_audit` fits into a comprehensive security
workflow for Erlang/OTP projects, from development through production.

## The vulnerability detection stack

No single tool catches everything. A layered approach uses multiple databases
and detection methods:

```
┌─────────────────────────────────────────────────┐
│                  Development                     │
│  rebar3 audit --level high (pre-push)           │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│                  Pull Request                    │
│  rebar3_audit → GitHub Advisory DB              │
│  rebar3_sbom + Grype → NVD + multiple feeds     │
│  Results posted as unified PR comment           │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│                  Main Branch                     │
│  Dependency Submission → GitHub Dependency Graph │
│  Dependabot alerts for new advisories           │
└───────────────────────┬─────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────┐
│                  Scheduled                       │
│  Weekly cron audit for new advisories           │
│  on existing locked versions                    │
└─────────────────────────────────────────────────┘
```

## Setting up the full pipeline

### 1. Add plugins to your project

```erlang
%% rebar.config
{project_plugins, [
    erlfmt,
    rebar3_audit,
    rebar3_sbom
]}.
```

### 2. Configure CI

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # Re-scan weekly for new advisories

permissions:
  contents: write
  pull-requests: write

jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      otp-version: '28'
      enable-audit: true
      enable-sbom: true
      enable-sbom-scan: true
      enable-dependency-submission: true
```

### 3. What each layer catches

**rebar3_audit** queries the GitHub Advisory Database which is curated and
Erlang-ecosystem-aware. It knows about Hex packages specifically and tracks
advisories filed under the `erlang` ecosystem.

**SBOM + Grype** generates a CycloneDX bill of materials and scans it against
NVD and other vulnerability feeds. Grype uses CPE matching which can catch
vulnerabilities reported against the upstream C/C++ libraries that NIFs wrap,
not just Hex-level advisories.

**Dependency Submission** feeds your dependency graph to GitHub, enabling
Dependabot alerts. This provides continuous monitoring — when a new advisory
is published weeks after you merged, you'll still get notified.

## Handling findings

### Triage workflow

1. **Check the advisory** — read the GHSA/CVE details. Is the vulnerable
   code path actually used in your application?
2. **Check for a fix** — if a patched version exists, upgrade. If not,
   evaluate the risk.
3. **Ignore if not applicable** — use `--ignore GHSA-xxxx` for advisories
   that don't affect your usage. Document why in a comment in your CI config.
4. **Track unpatched issues** — for vulnerabilities with no fix, create a
   tracking issue and set a reminder to check back.

### Ignoring advisories safely

```yaml
# Document why each ignore is justified
- name: Audit
  run: |
    rebar3 audit \
      --ignore GHSA-xxxx-yyyy-zzzz  # jose: we don't use JWT, only signing
```

### Severity-based gating

For projects where some low-severity findings are acceptable:

```yaml
jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      enable-audit: true
      audit-level: 'high'      # Block high + critical
      enable-sbom-scan: true    # Grype blocks high + critical by default
```

## JSON output schema

When using `--format json`, `rebar3_audit` outputs:

```json
{
  "vulnerabilities": [
    {
      "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
      "cve_id": "CVE-2025-1234",
      "package": "cowboy",
      "current_version": "2.10.0",
      "severity": "high",
      "vulnerable_range": "< 2.12.0",
      "patched_version": "2.12.0",
      "summary": "HTTP request smuggling vulnerability",
      "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
    }
  ],
  "dependencies_scanned": 12
}
```

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `ghsa_id` | string | GitHub Security Advisory identifier |
| `cve_id` | string \| null | CVE identifier (null if not assigned) |
| `package` | string | Hex package name |
| `current_version` | string | Version in your `rebar.lock` |
| `severity` | string | `critical`, `high`, `medium`, or `low` |
| `vulnerable_range` | string | Affected version range (e.g. `>= 1.0, < 2.0`) |
| `patched_version` | string \| null | First safe version (null if no fix) |
| `summary` | string | Advisory description |
| `url` | string | Link to the full advisory |

This schema is consumed by [erlang-ci](https://github.com/Taure/erlang-ci)
to render PR summary comments.

## Rate limiting

The GitHub Advisory API has rate limits:

| Auth | Limit |
|------|-------|
| No token | 60 requests/hour |
| `GITHUB_TOKEN` | 5,000 requests/hour |

In CI, `GITHUB_TOKEN` is automatically available. For local development,
set `GITHUB_TOKEN` in your shell environment or pass `--token` explicitly.

A single audit run makes 1 request per 100 advisories in the Erlang
ecosystem. As of 2025, this is typically 1-2 requests per run.
