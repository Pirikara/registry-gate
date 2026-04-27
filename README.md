# Registory Gate

Self-hosted registry proxy that enforces organizational package policies before download — no malware DB required.

Instead of signature scanning, Registory Gate applies **rule-based policies** defined in a YAML file:

- **Cooldown** — block packages published less than N days ago
- **Trust downgrade** — block versions whose provenance or publisher trust signals regressed vs. the version baseline
- **Allow / Deny** — explicit per-package overrides

Supported ecosystems: npm, PyPI, RubyGems, Docker, Homebrew.

---

## How it works

```
developer  →  Registory Gate (proxy)  →  upstream registry
                      │
                  policy check
                  (YAML rules)
                      │
               allow → 302 to tarball
               block → 451 Unavailable For Legal Reasons
```

The proxy rewrites metadata responses so package managers resolve tarballs through the proxy. Policy is evaluated at the metadata stage. Blocked packages never reach the client.

All events are logged to stdout as structured JSON. Optionally, events are also written to a local SQLite file for querying via the admin UI.

---

## Quickstart

**No external dependencies required** (no Postgres, no Redis).

### go run

```bash
# proxy on :8080
POLICY_FILE=examples/policy.yaml go run ./cmd/proxy

# admin API on :8081 (optional)
go run ./cmd/admin
```

### docker compose

```bash
docker compose up --build
```

Then point your package manager at `http://localhost:8080`:

```bash
npm install --registry http://localhost:8080 lodash
pip install --index-url http://localhost:8080/pypi/simple/ requests
```

For organisation-wide rollout via MDM (Jamf / Intune / Workspace ONE) or
configuration management (Ansible), use the per-platform setup scripts in
[`examples/clients/`](examples/clients/). They write system-default
registry config for npm / pip / RubyGems / Docker and verify connectivity.

---

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `POLICY_FILE` | *(none)* | Path to `policy.yaml`. If unset, all requests are allowed. |
| `DATABASE_URL` | *(none)* | SQLite DSN e.g. `file:./downloads.db`. If unset, log-only mode. |
| `PORT` | `8080` | Proxy listen port |
| `ADMIN_PORT` | `8081` | Admin API listen port |
| `REDIS_ADDR` | *(none)* | Redis address for shared cache (multi-replica). Defaults to in-memory. |
| `UPSTREAM_NPM` | `https://registry.npmjs.org` | Upstream npm registry |
| `UPSTREAM_PYPI` | `https://pypi.org` | Upstream PyPI |
| `PROXY_NPM_BASE_URL` | `http://localhost:8080` | Public base URL rewritten into npm metadata |

### Attribution (optional)

Registory Gate has no built-in authentication. If you run it behind a reverse proxy that injects `X-Forwarded-User` (e.g. oauth2-proxy, Authelia), the value is captured as `principal_label` in the download log.

---

## Policy file

Rules are evaluated top-to-bottom. The first matching `allow` short-circuits
and lets the package through. Otherwise every matching rule runs; any block
denies the request.

Each entry has exactly one rule kind as its top-level key.

```yaml
version: 1

rules:
  # Allow comes first so it short-circuits the rest.
  - allow: [npm:lodash, npm:react]

  # Hard deny.
  - deny: [npm:example-malicious-pkg]

  # Block packages younger than 7 days.
  - cooldown:
      min_age_days: 7
      ecosystems: [npm, pypi]

  # Block versions whose trust signals regressed vs. recent baseline.
  - trust_downgrade:
      ecosystems: [npm, pypi, rubygems]
      watch: [provenance.present, publisher.type, publisher.two_factor]
      on_unknown: warn   # warn | block | ignore
```

Package references use `ecosystem:name` shorthand. See
[`examples/policy.yaml`](examples/policy.yaml) for the full syntax.

### Rule kinds

| Kind | Description |
|---|---|
| `cooldown` | Block if the version was published less than `min_age_days` ago |
| `trust_downgrade` | Block if watched trust fields regressed vs. other recent versions |
| `allow` | Explicitly allow listed packages (bypass lower-priority rules) |
| `deny` | Explicitly block listed packages |
| `min_downloads` | Block if the package has fewer than `threshold` total downloads |

### Trust signal availability per ecosystem

`trust_downgrade` compares signals across recent versions. What's actually
observable depends on what each registry exposes via its public API:

| Registry | Provenance | Publisher | 2FA | Signature | Notes |
|---|---|---|---|---|---|
| **npm** | ✅ | ✅ | ✅ | — | sigstore attestations + `_npmUser.trustedPublisher` from JSON API |
| **PyPI** | ✅ | ✅ | — | — | PEP 740 endpoint (`/integrity/.../provenance`) — fetched per file |
| **RubyGems** | ❌ | ✅ | ✅ | — | `metadata.rubygems_mfa_required` per version |
| **Docker** | ⚠️ | ⚠️ | — | — | OCI annotations + heuristic for official `library/*` images |
| **Homebrew** | ❌ | ⚠️ | — | — | Only `tap == homebrew/core` distinguishes official formulae |

For Homebrew, `trust_downgrade` is effectively a no-op — there is no per-version
trust evidence to compare. Scope the rule to ecosystems where it has signal:

```yaml
- trust_downgrade:
    ecosystems: [npm, pypi, rubygems]
    watch: [provenance.present, publisher.two_factor]
    on_unknown: warn
```

---

## Admin UI

The admin service exposes a read-only JSON API:

```
GET /api/v1/policy      # loaded policy (source file, rule list)
GET /api/v1/downloads   # download history (requires DATABASE_URL)
```

Query parameters for `/api/v1/downloads`: `ecosystem`, `package`, `outcome` (`allowed`/`blocked`), `from`, `to` (RFC 3339).

A Next.js dashboard is in [`web/admin-ui/`](web/admin-ui/).

---

## Development

```bash
# run tests (no Docker required)
go test ./...

# build binaries
go build ./cmd/proxy
go build ./cmd/admin
```

Tests use in-memory SQLite — no external services needed.

---

## License

MIT
