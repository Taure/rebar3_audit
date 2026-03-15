# GitHub Action

`rebar3_audit` ships as a standalone GitHub Action that can audit any Erlang
project without requiring the plugin in `rebar.config`. This is useful for
organizations that want to enforce auditing across all repos without modifying
each project's build config.

## Usage

```yaml
- uses: Taure/rebar3_audit@v1
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
```

The action:

1. Installs Erlang/OTP and rebar3
2. Temporarily injects `rebar3_audit` into the project's plugins
3. Runs the audit
4. Cleans up the injected plugin

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `token` | `${{ github.token }}` | GitHub token for API access |
| `ignore` | — | Comma-separated GHSA IDs to ignore |
| `format` | `human` | Output format: `human` or `json` |
| `level` | `low` | Minimum severity to fail: `critical`, `high`, `medium`, `low` |
| `otp-version` | `28` | Erlang/OTP version to install |
| `rebar3-version` | `3` | Rebar3 version to install |

## Examples

### Basic audit

```yaml
name: Security

on:
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday 8am

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Taure/rebar3_audit@v1
```

### Ignore known advisories

```yaml
- uses: Taure/rebar3_audit@v1
  with:
    ignore: 'GHSA-xxxx-yyyy-zzzz,GHSA-aaaa-bbbb-cccc'
    level: 'high'
```

### JSON output for custom processing

```yaml
- uses: Taure/rebar3_audit@v1
  with:
    format: 'json'
```

## Plugin vs Action

| | Plugin (`rebar.config`) | Action (`uses:`) |
|---|---|---|
| Setup | Add to `project_plugins` | Zero config |
| Local use | `rebar3 audit` works locally | CI only |
| Version control | Locked in `rebar.config` | Pinned in workflow |
| Best for | Projects you own | Org-wide enforcement |

For most projects, using the plugin with
[erlang-ci](https://github.com/Taure/erlang-ci) is the recommended approach.
The standalone action is best for scanning repos where you can't modify
`rebar.config`.
