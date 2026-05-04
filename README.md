# Registry Gate

[![CI](https://github.com/pirikara/registry-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/pirikara/registry-gate/actions/workflows/ci.yml)

Self-hosted registry proxy that enforces organizational package policies before download — no malware DB required.

Instead of signature scanning, Registry Gate applies **rule-based policies** defined in a YAML file:

- **Cooldown** — block packages published less than N days ago
- **Trust downgrade** — block versions whose provenance or publisher trust signals regressed vs. the version baseline
- **Allow / Deny** — explicit per-package overrides

Supported ecosystems: npm, PyPI, RubyGems, Composer/Packagist, Docker,
Homebrew, Maven, NuGet, Cargo, Go modules.

---

## How it works

```
developer  →  Registry Gate (proxy)  →  upstream registry
                      │
                  policy check
                  (YAML rules)
                      │
               allow → 302 to tarball
               block → 403 Forbidden
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
composer config repositories.registry-gate composer http://localhost:8080
dotnet nuget add source http://localhost:8080/nuget/v3/index.json -n registry-gate
GOPROXY=http://localhost:8080/gomod,off go list -m golang.org/x/text@latest
```

Maven/Gradle should point at `http://localhost:8080/maven2/`; Cargo should use
source replacement with `sparse+http://localhost:8080/cargo/index/`; Go should
use `GOPROXY=http://localhost:8080/gomod,off` so the public `direct` fallback
cannot bypass policy.

For Composer enforcement, also disable the default Packagist repository in the
project or global Composer config so resolution cannot fall back around the
proxy:

```json
{
  "repositories": [
    {"type": "composer", "url": "http://localhost:8080"},
    {"packagist.org": false}
  ]
}
```

If a project already has a `composer.lock` generated against public Packagist,
run a lock metadata refresh after changing the repository config:

```bash
composer update --lock --no-install
```

This keeps package versions pinned, but rewrites lockfile metadata such as
`dist.url` so later `composer install` requests pass through Registry Gate.
Without this refresh, Composer installs from the URLs already stored in
`composer.lock`, bypassing any registry proxy.

For organisation-wide rollout via MDM (Jamf / Intune / Workspace ONE) or
configuration management (Ansible), use the per-platform setup scripts in
[`examples/clients/`](examples/clients/). They write system-default
registry config for npm / pip / RubyGems / Composer / Docker and verify connectivity.

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
| `UPSTREAM_GEMS` | `https://rubygems.org` | Upstream RubyGems |
| `UPSTREAM_COMPOSER` | `https://repo.packagist.org` | Upstream Composer/Packagist repository |
| `UPSTREAM_BREW` | `https://ghcr.io` | Upstream Homebrew bottle registry |
| `UPSTREAM_DOCKER` | `https://registry-1.docker.io` | Upstream Docker registry |
| `UPSTREAM_MAVEN` | `https://repo1.maven.org/maven2` | Upstream Maven repository |
| `UPSTREAM_NUGET` | `https://api.nuget.org/v3/index.json` | Upstream NuGet V3 service index |
| `UPSTREAM_CARGO_INDEX` | `https://index.crates.io` | Upstream Cargo sparse index |
| `UPSTREAM_CARGO_API` | `https://crates.io` | Upstream crates.io API |
| `UPSTREAM_GOMOD` | `https://proxy.golang.org` | Upstream Go module proxy |
| `PROXY_BASE_URL` | `http://localhost:8080` | Public base URL rewritten into package metadata |
| `PROXY_NPM_BASE_URL` | `http://localhost:8080` | Backward-compatible alias for `PROXY_BASE_URL` |

### Attribution (optional)

Registry Gate has no built-in authentication. If you run it behind a reverse proxy that injects `X-Forwarded-User` (e.g. oauth2-proxy, Authelia), the value is captured as `principal_label` in the download log.

---

## Policy file

Policy version 1 groups settings by package ecosystem. Package names inside an
ecosystem block are ecosystem-local and may use `*` globs. `allow` entries are
evaluated before other settings in the same ecosystem.

```yaml
version: 1

ecosystems:
  - package-ecosystem: npm
    allow:
      - "@company/*"
    deny:
      - example-malicious-pkg

    cooldown:
      default-days: 7
      include:
        - "*"
      exclude:
        - "@company/*"

    trust-downgrade:
      watch: [provenance.present, publisher.type, publisher.two_factor]
      on-unknown: warn   # warn | block | ignore

  - package-ecosystem: pypi
    cooldown:
      default-days: 5
      include: [requests, numpy, pandas*, django]
      exclude: [pandas]
```

The `package-ecosystem` value accepts Registry Gate names (`npm`, `pypi`,
`rubygems`, `composer`, `docker`, `homebrew`, `maven`, `nuget`, `cargo`,
`gomod`) and common aliases (`pip`, `bundler`, `gradle`, `go`). In Registry
Gate, ecosystem means the registry/protocol family, so npm-compatible clients
such as pnpm, Yarn, and Bun are governed by `npm`. See
[`examples/policy.yaml`](examples/policy.yaml) for the full syntax.

### Rule kinds

| Kind | Description |
|---|---|
| `cooldown` | Block if the version was published less than `default-days` ago |
| `trust-downgrade` | Block if watched trust fields regressed vs. other recent versions |
| `allow` | Explicitly allow listed package patterns (bypass lower-priority rules) |
| `deny` | Explicitly block listed packages |
| `min-downloads` | Block if the package's download count is below `threshold` (npm: last 30 days via downloads API; RubyGems: lifetime total) |

### Trust signal availability per ecosystem

`trust-downgrade` compares signals across recent versions. What's actually
observable depends on what each registry exposes via its public API:

| Registry | Provenance | Publisher | 2FA | Signature | Notes |
|---|---|---|---|---|---|
| **npm** | ✅ | ✅ | ✅ | — | sigstore attestations + `_npmUser.trustedPublisher` from JSON API |
| **PyPI** | ✅ | ✅ | — | — | PEP 740 endpoint (`/integrity/.../provenance`) — fetched per file |
| **RubyGems** | ❌ | ✅ | ✅ | — | `metadata.rubygems_mfa_required` per version |
| **Composer/Packagist** | ❌ | ❌ | — | — | p2 metadata exposes version time and dist/source URLs, but no publisher trust signal |
| **Docker** | ⚠️ | ⚠️ | — | — | OCI annotations + heuristic for official `library/*` images |
| **Homebrew** | ❌ | ⚠️ | — | — | Only `tap == homebrew/core` distinguishes official formulae |
| **Maven** | ❌ | ❌ | — | — | Cooldown uses artifact `Last-Modified` |
| **NuGet** | ❌ | ❌ | — | ⚠️ | Registration metadata exposes publish time/listed state; repository signatures are not yet enforced |
| **Cargo** | ❌ | ❌ | — | — | Sparse index exposes publish time and yanked state; crates.io trusted publishing can be added later |
| **Go modules** | ❌ | ❌ | — | — | Go proxy `.info` exposes version publish time |

For Homebrew, `trust-downgrade` is effectively a no-op — there is no per-version
trust evidence to compare. Scope the rule to ecosystems where it has signal:

```yaml
- package-ecosystem: npm
  trust-downgrade:
    watch: [provenance.present, publisher.two_factor]
    on-unknown: warn
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
go test -race ./...

# build binaries
go build ./cmd/proxy
go build ./cmd/admin
```

Tests use in-memory SQLite and httptest servers — no external services needed.
CI runs on every push and pull request via GitHub Actions (`.github/workflows/ci.yml`).

---

## License

MIT
