# ai-deploy-target

Guided setup for a machine that receives deployments from `ai-remote` (the
`ai-coding-v2` remote client). It installs a small forced-command gateway, a
target-owned app allowlist, per-app systemd units and an exact sudoers file on a
Debian/Ubuntu or Rocky Linux host. Supported app stacks: Node.js, Python,
static sites and Docker Compose.

Run it **as root on the target**, never on your workstation.

## Quick start

```sh
git clone https://github.com/tschokio/ai-deploy-target.git
cd ai-deploy-target

# 1. print what it would do, change nothing
sudo ./ai-deploy-target bootstrap --check

# 2. do it
sudo ./ai-deploy-target bootstrap

# 3. configure an app (interactive; prompts show defaults)
sudo ./ai-deploy-target app add my-app
```

`bootstrap` prints the SSH host key fingerprints at the end; type the ED25519
fingerprint into `ai-remote onboard <machine>` on your workstation so the VM
client pins the host key.

Every command is interactive by default. `--yes` accepts the defaults (and fails
when a required answer has no default and no flag). `--check` prints the plan and
changes nothing. Nothing here is automated and nothing touches the network
unless you confirm it.

## What it installs

| Path | Owner / mode | Purpose |
| --- | --- | --- |
| `/usr/local/lib/ai-deploy/gateway` | root 0755 | forced command (the only thing a deploy key can run) |
| `/usr/local/lib/ai-deploy/compose-up` | root 0755 | root-owned Docker Compose wrapper (exact sudo rule per app) |
| `/usr/local/lib/ai-deploy/VERSION` | root 0644 | installed package version |
| `/etc/ai-deploy/apps.json` | root 0644 | target-owned allowlist (created once, never overwritten) |
| `/etc/ai-deploy/<app>.env` | root:app-<app> 0640 | runtime secrets as `EnvironmentFile` (created empty) |
| `/etc/sudoers.d/ai-deploy` | root 0440 | one exact rule per restartable unit / compose app |
| `/etc/sudoers.d/ai-ops` | root 0440 | optional: `ai-ops ALL=(ALL:ALL) NOPASSWD: ALL` (TOTP-gated AI access) |
| `/srv/ai-deploy/` | ai-deploy 0755 | deploy user home |
| `/srv/ai-deploy/.ssh/authorized_keys` | ai-deploy 0600 | `restrict,command="…/gateway" <VM deploy key>` |
| `/var/lib/ai-ops/.ssh/authorized_keys` | ai-ops 0600 | optional: the `from="…"`-restricted AI ops key |
| `/srv/ai-deploy/<app>/` | ai-deploy 0755 | `mirror.git`, `releases/`, `current`, `history.jsonl` |
| `/srv/ai-deploy/<app>/.ssh/github_ed25519` | ai-deploy 0600 | per-app GitHub read-only deploy key |
| `/srv/ai-deploy/<app>/.ssh/known_hosts` | ai-deploy 0644 | pinned GitHub host keys |
| `/etc/systemd/system/ai-app-<app>.service` | root 0644 | generated unit (service apps) |
| `/var/lib/ai-app-<app>/` | app-<app> | writable app data (systemd `StateDirectory`) |

The deploy user `ai-deploy` is a system user with `/bin/sh` (the forced command
needs a shell) and a locked password. Each service app runs as its own
`app-<app>` system user with a nologin shell.

## Keys: which key goes where

| Key | Generated where | Add it to |
| --- | --- | --- |
| VM deploy key | on your workstation (`ai-remote keygen <machine>`) | the target: `bootstrap --deploy-key "…"` writes `/srv/ai-deploy/.ssh/authorized_keys` |
| VM admin key | your workstation | the admin user's `~<admin>/.ssh/authorized_keys` (that user's own login) |
| per-app GitHub key | on the target (app add) | the **repository**: GitHub → Settings → Deploy keys → Add deploy key, title `ai-deploy <host> <app>`, **leave "Allow write access" unchecked** (read-only) |

`ai-deploy-target bootstrap` manages `/srv/ai-deploy/.ssh/authorized_keys`
completely: it contains exactly the forced-command lines it wrote. Use
`--add-deploy-key` to keep the existing keys and add another.

## App kinds

- **service** — build steps + a generated systemd unit (`ai-app-<app>.service`).
  Presets: `node` (`npm ci`, optional `npm run build`), `python`
  (venv + `pip install -r requirements.txt`, gunicorn), or `custom`. Enable it
  with `systemctl enable` (the first deploy starts it).
- **static** — optional build, no unit. If nginx is installed it offers a server
  snippet under `/etc/nginx/conf.d/`, validates it with `nginx -t` and reloads.
  Otherwise it prints nginx and Caddy snippets.
- **compose** — Docker Compose via the root-owned `compose-up` wrapper; treat the
  repository as **root-equivalent code**.

## AI admin access (optional)

`bootstrap` can additionally prepare a **TOTP-gated AI admin account** (`ai-ops`) that the
VM helper uses for short, logged root sessions. It is off unless you pass `--ai-ops-key`
(or answer the prompt), and it can be managed later:

```sh
sudo ./ai-deploy-target ai-ops enable --key "ssh-ed25519 AAAA… ai-ops@vm" --from 203.0.113.5
sudo ./ai-deploy-target ai-ops status
sudo ./ai-deploy-target ai-ops disable
```

- `ai-ops` is a system user (home `/var/lib/ai-ops`, shell `/bin/bash`, password locked)
  whose `authorized_keys` holds exactly one key, with `/etc/sudoers.d/ai-ops` granting
  `ai-ops ALL=(ALL:ALL) NOPASSWD: ALL` (visudo-checked, mode 0440).
- The key is `from="…"`-restricted to the given addresses/CIDRs (comma-separated, max 8).
  **Without `--from` the key is accepted from any source** and bootstrap warns loudly.
- Access is granted **on the VM** with the admin TOTP code (`ai-remote admin grant <m>`) for
  at most **60 minutes**; every command is logged and access can be revoked at any time.
  The target key stays installed until `ai-ops disable`, which removes the key and the sudo
  rule, locks the password and sets the shell to `nologin` (the user is kept).
- During onboarding: `bootstrap --ai-ops-key KEY --ai-ops-from CIDR[,CIDR…]`; the source
  defaults to the connecting SSH client's IP and re-running bootstrap is idempotent.

## Rocky Linux / SELinux

On Rocky (SELinux enforcing) bootstrap registers file contexts so the deploy tree
is usable:

```sh
semanage fcontext -a -t ssh_home_t '/srv/ai-deploy/\.ssh(/.*)?'
semanage fcontext -a -t bin_t '/srv/ai-deploy/[^/]+/releases/[^/]+/(\.venv/bin|node_modules/\.bin)(/.*)?'
semanage fcontext -a -t httpd_sys_content_t '/srv/ai-deploy/[^/]+/releases(/.*)?'
restorecon -R /srv/ai-deploy
```

When AI admin access is enabled, bootstrap also registers
`semanage fcontext -a -t ssh_home_t '/var/lib/ai-ops/\.ssh(/.*)?'` and runs
`restorecon -R /var/lib/ai-ops`.

The rules are idempotent (`-m` when the rule already exists). Debian uses the
`sudo` group, Rocky uses `wheel`. The nologin shell is whichever of
`/usr/sbin/nologin` or `/sbin/nologin` exists.

## Updating

```sh
cd ai-deploy-target
git pull
sudo ./ai-deploy-target bootstrap
```

Bootstrap is idempotent: it re-installs the gateway/compose wrapper/VERSION
atomically and never overwrites `apps.json`.

## Uninstall

```sh
sudo ./ai-deploy-target uninstall           # remove the code and rules, keep app data
sudo ./ai-deploy-target uninstall --purge   # also remove app data, users, env files, state dirs
```

## Security model

- `/srv/ai-deploy/.ssh/authorized_keys` forces every deploy key through
  `restrict,command="/usr/local/lib/ai-deploy/gateway"` — no shell, no forwarding,
  no pty.
- The gateway runs one of a fixed set of operations, reads the allowlist
  `/etc/ai-deploy/apps.json` as root, and never starts a shell.
- sudoers grants `ai-deploy` exactly one `systemctl restart <unit>` per service
  app (and one `compose-up <app>` per compose app), validated with `visudo -cf`.
- Service apps run unprivileged as `app-<app>` with `NoNewPrivileges`,
  `ProtectSystem=full`, `ProtectHome=yes` and `PrivateTmp=yes`.
- **Compose apps are root-equivalent**: the wrapper runs `docker compose` as root.
  Only add compose repositories you trust.
- `PermitRootLogin no` is written as a drop-in only after you confirm that admin
  login works in a second terminal; the drop-in is removed again if `sshd -t`
  rejects it.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 tschokio.
