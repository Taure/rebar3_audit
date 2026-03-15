# CI Integration

`rebar3_audit` integrates with CI pipelines in two ways: as a rebar3 plugin
in your own workflow, or via the
[erlang-ci](https://github.com/Taure/erlang-ci) reusable workflow which
handles setup, caching, and PR reporting automatically.

## Using erlang-ci (recommended)

The easiest way to add vulnerability scanning to your Erlang project:

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  pull-requests: write  # Required for PR summary comments

jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      otp-version: '28'
      enable-audit: true
```

This gives you:

- Automatic vulnerability scanning on every PR and push
- A PR comment summarizing audit results (updated on re-runs, never duplicated)
- Configurable severity threshold via `audit-level`

### Severity threshold

By default, any vulnerability fails the build. To only fail on high or
critical:

```yaml
jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      otp-version: '28'
      enable-audit: true
      audit-level: 'high'
```

### Combined with SBOM scanning

For defense in depth, enable both audit and SBOM scanning. They use different
vulnerability databases (GitHub Advisory Database vs Grype/NVD) and catch
different things:

```yaml
jobs:
  ci:
    uses: Taure/erlang-ci/.github/workflows/ci.yml@v1
    with:
      otp-version: '28'
      enable-audit: true
      enable-sbom: true
      enable-sbom-scan: true
```

Both results appear in a single PR comment — audit findings in one section,
SBOM scan findings in another.

### Full security pipeline

```yaml
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

This gives you three layers of vulnerability detection:

| Layer | Tool | Database | Output |
|-------|------|----------|--------|
| Audit | `rebar3_audit` | GitHub Advisory Database | PR comment + check |
| SBOM Scan | Grype | NVD + multiple feeds | PR comment + check |
| Dependency Submission | GitHub Dependabot | GitHub Advisory Database | Security tab alerts |

## Custom workflow setup

If you're not using erlang-ci, add the audit step to your own workflow:

```yaml
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: erlef/setup-beam@v1
        with:
          otp-version: '28'
          rebar3-version: '3'
      - run: rebar3 compile
      - name: Audit dependencies
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: rebar3 audit
```

The `GITHUB_TOKEN` is optional but recommended — without it you're limited
to 60 GitHub API requests per hour, which can cause rate limiting in busy
CI environments.

### JSON output for downstream processing

```yaml
- name: Audit dependencies
  id: audit
  run: |
    output=$(rebar3 audit --format json 2>&1)
    # Parse and use the JSON output...
```

## Pre-push hook

For local development, add an audit check to your pre-push workflow:

```bash
# In your pre-push checklist
rebar3 fmt --check
rebar3 xref
rebar3 dialyzer
rebar3 eunit
rebar3 audit --level high  # Allow low/medium locally, catch high+ in CI
```

This catches critical issues before they reach CI while keeping the local
feedback loop fast.
