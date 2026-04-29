#!/usr/bin/env bash
# Registry Gate — macOS client setup script.
#
# Designed to be run from MDM (Jamf, Intune for macOS, Workspace ONE) as root.
# Configures npm / pip / RubyGems / Docker Desktop to use the proxy as the
# system-default registry.
#
# Required:
#   REGISTORY_GATE_URL — e.g. https://rg.corp.example.com
#
# CA trust, network-level enforcement, and certificate distribution are
# explicitly out of scope; rely on your existing MDM CA-distribution profile.
#
# Idempotent.

set -euo pipefail

if [[ -z "${REGISTORY_GATE_URL:-}" ]]; then
  echo "ERROR: REGISTORY_GATE_URL is required" >&2
  exit 64
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: must run as root" >&2
  exit 77
fi

URL="${REGISTORY_GATE_URL%/}"

log()   { echo "[registry-gate] $*"; }
fatal() { echo "[registry-gate] FATAL: $*" >&2; exit 1; }

# npm — system-wide npmrc
log "writing /etc/npmrc"
cat > /etc/npmrc <<EOF
registry=$URL
EOF

# pip — system-wide config
PIP_CONF="/Library/Application Support/pip/pip.conf"
mkdir -p "$(dirname "$PIP_CONF")"
log "writing $PIP_CONF"
cat > "$PIP_CONF" <<EOF
[global]
index-url = $URL/pypi/simple/
EOF

# RubyGems — system-wide gemrc
log "writing /etc/gemrc"
cat > /etc/gemrc <<EOF
:sources:
  - $URL
EOF

# Homebrew — system-wide bottle domain
log "writing /etc/zshenv for Homebrew bottle domain"
# macOS default shell is zsh. For bash, /etc/profile or /etc/bashrc would be needed.
if ! grep -q "HOMEBREW_BOTTLE_DOMAIN" /etc/zshenv 2>/dev/null; then
  echo "export HOMEBREW_BOTTLE_DOMAIN=\"$URL\"" >> /etc/zshenv
fi

# Docker Desktop — per-user daemon.json (Docker Desktop reads from user's home)
log "seeding Docker Desktop registry mirror per user"
for HOME_DIR in /Users/*; do
  USER_NAME=$(basename "$HOME_DIR")
  [[ "$USER_NAME" == "Shared" || "$USER_NAME" == ".localized" ]] && continue
  [[ -d "$HOME_DIR" ]] || continue
  install -d -m 0755 -o "$USER_NAME" "$HOME_DIR/.docker"
  cat > "$HOME_DIR/.docker/daemon.json" <<EOF
{ "registry-mirrors": ["$URL"] }
EOF
  chown "$USER_NAME" "$HOME_DIR/.docker/daemon.json"
done

# Verify connectivity
log "verifying $URL/health"
if ! curl --fail --silent --show-error --max-time 10 "$URL/health" >/dev/null; then
  fatal "proxy unreachable at $URL/health"
fi

log "OK"
