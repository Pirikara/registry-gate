POLICY_FILE     ?= examples/policy.yaml
DATABASE_URL    ?= file:./downloads.db
PROXY_URL       ?= http://localhost:8080

.PHONY: dev proxy admin ui setup configure unconfigure test build clean help

## setup: configure local package managers to use the proxy
setup:
	go mod download
	$(MAKE) configure

# --- configure / unconfigure helpers ---
# All configuration is done by writing files directly — no tool commands are
# invoked, so configure works even if the tool (yarn, pip, etc.) isn't installed.

## configure: point npm / yarn / pip / gem / Composer / Docker at the local proxy
configure:
	@echo "→ ~/.npmrc  (npm / pnpm / bun / yarn v1)"
	@sed -i '' '/^registry=/d' ~/.npmrc 2>/dev/null; \
	  printf 'registry=%s\n' "$(PROXY_URL)" >> ~/.npmrc
	@echo "→ ~/.yarnrc.yml  (yarn v2+)"
	@sed -i '' '/^npmRegistryServer:/d' ~/.yarnrc.yml 2>/dev/null; \
	  printf 'npmRegistryServer: "%s"\n' "$(PROXY_URL)" >> ~/.yarnrc.yml
	@echo "→ ~/.config/pip/pip.conf  (pip / uv)"
	@mkdir -p ~/.config/pip
	@printf '[global]\nindex-url = %s/pypi/simple/\n' "$(PROXY_URL)" > ~/.config/pip/pip.conf
	@echo "→ ~/.gemrc  (gem)"
	@printf ':sources:\n  - %s\n' "$(PROXY_URL)" > ~/.gemrc
	@echo "→ ~/.bundle/config  (bundler)"
	@mkdir -p ~/.bundle
	@sed -i '' '/^BUNDLE_MIRROR/d' ~/.bundle/config 2>/dev/null; \
	  printf 'BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "%s"\n' "$(PROXY_URL)" >> ~/.bundle/config
	@echo "→ ~/.config/composer/config.json  (Composer)"
	@mkdir -p ~/.config/composer
	@printf '{\n  "repositories": [\n    {"type": "composer", "url": "%s"},\n    {"packagist.org": false}\n  ]\n}\n' "$(PROXY_URL)" > ~/.config/composer/config.json
	@echo "→ ~/.docker/daemon.json  (Docker Desktop — restart required)"
	@mkdir -p ~/.docker
	@printf '{"registry-mirrors":["%s"]}\n' "$(PROXY_URL)" > ~/.docker/daemon.json

## unconfigure: restore all package managers to public registries
unconfigure:
	@echo "→ ~/.npmrc"
	@sed -i '' '/^registry=/d' ~/.npmrc 2>/dev/null; \
	  printf 'registry=https://registry.npmjs.org\n' >> ~/.npmrc
	@echo "→ ~/.yarnrc.yml"
	@sed -i '' '/^npmRegistryServer:/d' ~/.yarnrc.yml 2>/dev/null || true
	@echo "→ ~/.config/pip/pip.conf"
	@sed -i '' '/^index-url/d' ~/.config/pip/pip.conf 2>/dev/null || true
	@echo "→ ~/.gemrc"
	@printf ':sources:\n  - https://rubygems.org\n' > ~/.gemrc
	@echo "→ ~/.bundle/config"
	@sed -i '' '/^BUNDLE_MIRROR/d' ~/.bundle/config 2>/dev/null || true
	@echo "→ ~/.config/composer/config.json"
	@printf '{}\n' > ~/.config/composer/config.json
	@echo "→ ~/.docker/daemon.json"
	@printf '{}\n' > ~/.docker/daemon.json

## dev: start proxy + admin API + admin UI (Ctrl-C stops all)
dev:
	@test -d web/admin-ui/node_modules || pnpm --dir web/admin-ui install
	@echo "Starting proxy :8080 / admin :8081 / ui :3000"
	@trap 'kill 0' INT; \
	  POLICY_FILE=$(POLICY_FILE) DATABASE_URL=$(DATABASE_URL) go run ./cmd/proxy & \
	  DATABASE_URL=$(DATABASE_URL) go run ./cmd/admin & \
	  (cd web/admin-ui && pnpm run dev) & \
	  wait

## proxy: start proxy only
proxy:
	POLICY_FILE=$(POLICY_FILE) DATABASE_URL=$(DATABASE_URL) go run ./cmd/proxy

## admin: start admin API only
admin:
	DATABASE_URL=$(DATABASE_URL) go run ./cmd/admin

## ui: start admin UI only (installs node_modules on first run)
ui:
	@test -d web/admin-ui/node_modules || pnpm --dir web/admin-ui install
	cd web/admin-ui && pnpm run dev

## test: run all Go tests
test:
	go test ./...

## build: compile proxy and admin binaries
build:
	go build -trimpath -o proxy ./cmd/proxy
	go build -trimpath -o admin ./cmd/admin

## clean: remove built binaries and local SQLite files
clean:
	rm -f proxy admin
	rm -f downloads.db downloads.db-wal downloads.db-shm

help:
	@grep -E '^## ' Makefile | sed 's/^## //'
