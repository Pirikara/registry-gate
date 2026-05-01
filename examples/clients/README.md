# Client setup scripts

These scripts configure a workstation to use Registry Gate as the default
registry for npm / pip / RubyGems / Composer / Docker. They are designed to be
deployed via MDM (Jamf, Intune, Workspace ONE) or configuration management
(Ansible).

| Script | Target | Run as |
|---|---|---|
| `setup-macos.sh`    | macOS (Jamf, Intune for macOS)              | root |
| `setup-linux.sh`    | Linux (Debian/Ubuntu, RHEL/Fedora families) | root |
| `setup-windows.ps1` | Windows (Intune)                            | SYSTEM / Administrator |

Each script is idempotent: re-running overwrites existing state without
accumulating duplicates.

---

## What they do

1. Write registry configuration for npm, pip, RubyGems, Composer, and Docker so
   the package manager defaults to the proxy URL.
2. Verify connectivity by hitting `<proxy>/health`. Non-zero exit on failure
   so MDM reports the device as non-compliant.

That's it. The scripts are intentionally narrow.

## What they do NOT do (and why)

- **CA certificate trust.** If the proxy is served over HTTPS with an
  internal CA, distribute that CA via your existing infrastructure — every
  MDM ships a Trusted Root / Certificate profile feature that handles this
  generically. It's not specific to Registry Gate.
- **Hard enforcement against user override.** `~/.npmrc` always wins over
  `/etc/npmrc`; locking the system file down creates false confidence. If
  you need to *force* traffic through the proxy, block the public registries
  at the network layer (`registry.npmjs.org`, `pypi.org`, `rubygems.org`,
  `repo.packagist.org`, `registry-1.docker.io`).
- **CI runner setup.** Self-hosted runners need their own configuration —
  bake the proxy URL into the runner image rather than running this script
  inside CI.
- **Homebrew.** Homebrew has no built-in registry-redirect mechanism;
  mirror the bottle CDN at the network layer if you need it covered.

## Inputs

| Variable / parameter | Required | Example |
|---|---|---|
| `REGISTORY_GATE_URL` / `-ProxyURL` | yes | `https://rg.corp.example.com` |

---

## MDM deployment recipes

### Jamf (macOS)

1. Add `setup-macos.sh` as a Script payload in a Jamf Policy.
2. Pass `REGISTORY_GATE_URL` via the policy's environment or a wrapper
   script that exports it before invoking ours.
3. Scope to the developer smart group; trigger at recurring check-in.

### Intune (Windows)

1. Devices → Scripts and remediations → Platform scripts → Add → Windows.
2. Upload `setup-windows.ps1`. Run as: `System`.
3. Either hard-code the `$ProxyURL` default at the top of the script before
   uploading, or wrap the script:

   ```powershell
   & "$PSScriptRoot\setup-windows.ps1" -ProxyURL "https://rg.corp.example.com"
   ```

### Intune (macOS)

Use Devices → macOS → Shell scripts. Wrap the script to inject the env var:

```bash
#!/usr/bin/env bash
export REGISTORY_GATE_URL="https://rg.corp.example.com"
exec /Library/Application\ Support/registry-gate/setup-macos.sh
```

### Ansible (Linux)

```yaml
- hosts: developer_workstations
  become: true
  tasks:
    - copy:
        src: ../examples/clients/setup-linux.sh
        dest: /usr/local/sbin/registry-gate-setup
        mode: '0755'
    - command: /usr/local/sbin/registry-gate-setup
      environment:
        REGISTORY_GATE_URL: https://rg.corp.example.com
```

---

## Verifying after deployment

On a target device:

```bash
npm config get registry           # → https://rg.corp.example.com/
pip config get global.index-url   # → https://rg.corp.example.com/pypi/simple/
gem sources --list                # → contains rg.corp.example.com
composer config repositories      # → contains rg.corp.example.com and disables packagist.org
docker info | grep -i mirror      # → Registry Mirrors: rg.corp.example.com
```

For existing PHP projects, refresh `composer.lock` once after applying the
Composer repository config:

```bash
composer update --lock --no-install
```

This preserves the locked package versions while replacing public Packagist
download URLs with Registry Gate URLs. Existing lockfiles otherwise keep using
the URLs that were written before the proxy was configured.
