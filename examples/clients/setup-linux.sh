#!/usr/bin/env bash
# Registry Gate — Linux client setup script.
#
# Designed to be run from configuration management (Ansible, Chef, Puppet,
# Workspace ONE Linux) as root.
#
# Required:
#   REGISTORY_GATE_URL
#
# CA trust and network-level enforcement are out of scope; rely on existing
# infrastructure for those.
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

log "writing /etc/npmrc"
cat > /etc/npmrc <<EOF
registry=$URL
EOF

log "writing /etc/pip.conf"
cat > /etc/pip.conf <<EOF
[global]
index-url = $URL/pypi/simple/
EOF

log "writing /etc/gemrc"
cat > /etc/gemrc <<EOF
:sources:
  - $URL
EOF

# Composer — per-user global config for root and existing local users.
log "seeding Composer repository per user"
for HOME_DIR in /root /home/*; do
  [[ -d "$HOME_DIR" ]] || continue
  USER_NAME=$(basename "$HOME_DIR")
  [[ "$HOME_DIR" == "/root" ]] && USER_NAME="root"
  id "$USER_NAME" >/dev/null 2>&1 || continue
  install -d -m 0755 -o "$USER_NAME" "$HOME_DIR/.config/composer"
  cat > "$HOME_DIR/.config/composer/config.json" <<EOF
{
  "repositories": [
    {"type": "composer", "url": "$URL"},
    {"packagist.org": false}
  ]
}
EOF
  chown "$USER_NAME" "$HOME_DIR/.config/composer/config.json"
done

# Docker daemon — system-wide; requires daemon restart to take effect.
if command -v docker >/dev/null 2>&1; then
  install -d -m 0755 /etc/docker
  log "writing /etc/docker/daemon.json (daemon restart required)"
  cat > /etc/docker/daemon.json <<EOF
{ "registry-mirrors": ["$URL"] }
EOF
  if systemctl is-active docker >/dev/null 2>&1; then
    log "restarting docker"
    systemctl restart docker
  fi
fi

log "verifying $URL/health"
if ! curl --fail --silent --show-error --max-time 10 "$URL/health" >/dev/null; then
  fatal "proxy unreachable at $URL/health"
fi

log "OK"
