# rebar3_audit

Audit rebar3 dependencies for known vulnerabilities using the [GitHub Advisory Database](https://github.com/advisories?query=ecosystem%3Aerlang).

The Erlang equivalent of [`mix_audit`](https://github.com/mirego/mix_audit).

## Usage

Add to your `rebar.config`:

```erlang
{project_plugins, [
    {rebar3_audit, {git, "https://github.com/Taure/rebar3_audit.git", {tag, "v0.1.0"}}}
]}.
```

Then run:

```bash
rebar3 audit
```

## GitHub Actions

Add to your workflow:

```yaml
- name: Inject rebar3_audit plugin
  run: |
    echo '{project_plugins, [{rebar3_audit, {git, "https://github.com/Taure/rebar3_audit.git", {tag, "v0.1.0"}}}]}.' >> rebar.config

- name: Audit dependencies
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: rebar3 audit --token "${GITHUB_TOKEN}"

- name: Clean up
  if: always()
  run: git checkout rebar.config
```

The `GITHUB_TOKEN` increases the API rate limit from 60 to 5000 requests/hour.

## Options

| Flag | Env var | Description |
|------|---------|-------------|
| `--token` | `GITHUB_TOKEN` | GitHub token for API access |
| `--ignore GHSA-xxxx` | | Skip a specific advisory (repeat for multiple) |
| `--format human\|json` | | Output format (default: human) |

## Example output

```
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

## How it works

1. Reads `rebar.lock` for hex dependency names and versions
2. Fetches advisories from the [GitHub Advisory Database REST API](https://docs.github.com/en/rest/security-advisories/global-advisories) (erlang ecosystem)
3. Matches each dependency version against advisory version ranges
4. Reports vulnerabilities and exits with code 1 if any are found

## Requirements

- OTP 27+ (uses `json:decode/1`)
- `rebar.lock` must exist (run `rebar3 lock` first)

## License

Apache-2.0
