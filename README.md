# IPWall

IPWall is a lightweight Flask app for self-service IP allowlisting behind an auth proxy (such as `oauth2-proxy`) and reverse proxy middleware (such as Traefik IP whitelisting).

Users can add/refresh their current IP, and admins can request temporary SSH access per IP with automatic expiry handled by a companion firewall sync script.

## What it does

- Authenticated users can register their current client IP.
- Registered IPs are timestamped and automatically expired after inactivity.
- The app continuously syncs all valid IPs into a whitelist YAML file for proxy enforcement.
- Admin users can mark an IP for temporary SSH access (1h, 2h, 4h, 8h, 12h, 24h).
- A host-side firewall sync script computes desired SSH access and reconciles local/remote targets.

## Repository layout

- `src/app.py` — Flask web app and YAML syncing logic.
- `src/templates/` — UI templates.
- `src/static/` — Bootstrap assets and icons.
- `ipscript/firewall_sync.py` — host-side timer reconciler that fans out desired state to SSH targets.
- `ipscript/remote_sync.py` — remote-side deterministic `iptables` reconciler.
- `ipscript/sync_schema.py` — pure payload/response validation helpers used by sync scripts.
- `ipscript/firewall_install.py` — installer/manager for the sync script (systemd or cron).
- `ipscript/ipwall-firewall.service` — sample systemd service unit.

## Requirements

- Python 3.11+
- Dependencies in `requirements.txt`:
  - `flask==2.3.2`
  - `PyYAML`
- For SSH firewall sync:
  - Linux with `iptables`
  - Root privileges for firewall changes
  - `systemd` or `cron` (depending on install method)

## Quick start (local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 src/app.py
```

The app listens on `0.0.0.0:8080`.

> Note: Direct local browser testing will fail by default unless your request appears to come from the trusted proxy CIDR (see `TRUSTED_PROXY_CIDR` below).

## Docker

Build and run:

```bash
docker build -t ipwall .
docker run --rm -p 8080:8080 \
  -e FLASK_SECRET_KEY='change-me' \
  -e TRUSTED_PROXY_CIDR='0.0.0.0/0' \
  -e UI_CONFIG_FILE='/app/config/ui_config.json' \
  -v $(pwd)/config/ui_config.json:/app/config/ui_config.json:ro \
  ipwall
```

The provided `Dockerfile` uses `python:3.11-alpine`, copies the repo into `/app`, installs requirements, copies `config/ui_config.example.json` to `config/ui_config.json` as the in-image default, and starts `python src/app.py`.

## Authentication and proxy expectations

IPWall expects to run behind an auth proxy that sets these headers:

- `X-Auth-Request-Email` (required)
- `X-Auth-Request-Groups` (optional, comma-separated)
- `X-Real-Ip` (optional; falls back to `remote_addr`)

Admin behavior is enabled when `admin` appears in `X-Auth-Request-Groups`.

## Security controls built in

- Trusted proxy enforcement: request `remote_addr` must be inside `TRUSTED_PROXY_CIDR`.
- CSRF protection for mutating routes via session token.
- In-memory per-identity rate limit on add/refresh route (20 req / 60s).
- IP address parsing/validation before persistence.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | random generated at startup | Flask session/CSRF signing key |
| `TRUSTED_PROXY_CIDR` | `172.20.0.0/16` | Allowed source range for reverse proxy |
| `UI_CONFIG_FILE` | `config/ui_config.json` | Path to JSON UI config containing dashboard service links and SSH targets |
| `UI_CONFIG_PATH` | `config/ui_config.json` | Backward-compatible alias for `UI_CONFIG_FILE` |

## UI service links config

The dashboard "Services" section and SSH target options are loaded from JSON at `UI_CONFIG_FILE` (default `config/ui_config.json`; falls back to `UI_CONFIG_PATH` for backward compatibility).

Initialize local config from the template:

```bash
cp config/ui_config.example.json config/ui_config.json
```

`service_links` is an array of groups. Each group requires:

- `id` (string)
- `heading` (string)
- `links` (array of link rows)

Each link row requires:

- `id` (string)
- `label` (string)
- `url` (string)

Optional fields:

- `icon` (string) — text/emoji shown before heading or link label, or an image path such as `icons/app1.png` (resolved under Flask `static/`).
- `copyable` (boolean) — render "Copy Link to Clipboard" button when `true`.
- `helper_text` (string) — render descriptive helper text above the displayed URL.

Malformed groups/rows are ignored. If the file is missing/invalid, IPWall logs a warning and falls back to built-in defaults (empty service links + empty SSH targets).

Example:

```json
{
  "service_links": [
    {
      "id": "app-1",
      "icon": "icons/app1.png",
      "heading": "The Wonderful App",
      "links": [
        {
          "id": "primary-app",
          "icon": "icons/open.png",
          "label": "Open APP",
          "url": "https://app1.example.com"
        },
        {
          "id": "apps-or-browser",
          "icon": "📋",
          "label": "Apps or Browser",
          "url": "https://app2.example.com",
          "copyable": true,
          "helper_text": "Apps must use this link to connect"
        }
      ]
    },
    {
      "id": "app-2",
      "icon": "✨",
      "heading": "The Beautiful App",
      "links": [
        {
          "id": "another-app",
          "icon": "🔗",
          "label": "Open APP",
          "url": "https://beautiful.example.com"
        }
      ]
    }
  ]
}
```

`icon` accepts either:
- Text/emoji (for example `"🚀"`), or
- Static file path (for example `"icons/app1.png"` or `"static/icons/app1.png"`), rendered via Flask `url_for('static', ...)`.

### Docker deployment notes

- This repo ships `config/ui_config.example.json` as a template.
- The Docker image copies this template to `/app/config/ui_config.json` during build as the runtime default.
- Create your real config as `config/ui_config.json` (gitignored) so future pulls do not overwrite it.
- To customize links/SSH targets without rebuilding, bind mount your config file and set `UI_CONFIG_FILE` if you use a different in-container location.
- Recommended mount: `-v /path/on/host/ui_config.json:/app/config/ui_config.json:ro`.

### Inject a custom UI config at runtime

Use a bind mount to provide a custom config file from the host:

```bash
docker run --rm -p 8080:8080 \
  -e FLASK_SECRET_KEY='change-me' \
  -e TRUSTED_PROXY_CIDR='0.0.0.0/0' \
  -e UI_CONFIG_FILE='/app/config/custom-ui.json' \
  -v /path/on/host/ui_config.json:/app/config/custom-ui.json:ro \
  ipwall
```

## Data files

By default the app writes in its working directory:

- `user_data.yml` — per-user IP records and optional SSH metadata.
- `ip_whitelist.yml` — proxy middleware source ranges.

### `user_data.yml` shape

```yaml
user@example.com:
  ips:
    - ip: 203.0.113.5
      last_seen: "2026-04-08T12:34:56.789012"
      ssh: true
      ssh_hours: 4
      enabledssh: false
      ssh_enabled_time: "2026-04-08T12:35:10.123456+00:00"
```

Notes:
- IP entries can be legacy strings; app normalizes them to objects.
- Non-admin users can add/refresh and remove only their own entries.
- IP entries are removed after 90 days of inactivity.

### `ip_whitelist.yml` shape

The app updates this path:

```yaml
http:
  middlewares:
    middlewares-local-ipwhitelist:
      ipWhiteList:
        sourceRange:
          - 203.0.113.5
          - 198.51.100.7
```

## Flask routes

- `GET /` — dashboard.
- `POST /add_ip` — add/refresh current IP; admins can request SSH.
- `POST /remove_ip` — remove one of the caller's IPs.
- `POST /revoke_ssh` — admin-only SSH revocation by IP.
- `POST /clear_all_users` — admin-only destructive reset (requires typing `YES`).

## SSH firewall sync architecture

Flask (`src/app.py`) only writes desired state (`user_data.yml` + `ip_whitelist.yml`).
Host-side reconciliation is performed by the timer job running `ipscript/firewall_sync.py`.

`ipscript/firewall_sync.py`:

- Reads `USER_DATA_FILE` (default `user_data.yml`).
- Computes desired SSH state per target from active `ssh_targets` grants.
- Loads target transport config from `UI_CONFIG_FILE`.
- Calls `remote_sync.py` locally (localhost targets) or over SSH (remote targets).
- Verifies returned applied state and writes per-target results to `REMOTE_SYNC_LOG_FILE` (default `remote_sync_results.log`).

`ipscript/remote_sync.py` (runs on each target host):

- Receives desired state JSON on stdin (`chain`, `target_id`, `request_id`, `ips`).
- Reconciles `iptables` rules atomically for the configured chain.
- Returns applied state JSON (`ok`, `applied_ips`, `missing`, `extra`, `errors`).

### Target mapping in config

Each `ssh_targets` entry in `config/ui_config.json` must be exactly one of these target types:

- **Remote target**: requires `remote_host` + `remote_user`; optional `remote_port` (default `22`) and `remote_script`.
- **Localhost target**: requires `"localhost": true` and must not define any `remote_*` fields. This target is reconciled locally (no SSH).

Ambiguous targets are rejected (ignored) during config parsing.

By default, only one localhost target is allowed. If you intentionally run a multi-chain localhost design, set top-level `allow_multiple_localhost_targets` to `true`.

Example:

```json
{
  "allow_multiple_localhost_targets": false,
  "ssh_targets": [
    {
      "id": "localhost",
      "name": "Local Firewall",
      "localhost": true
    },
    {
      "id": "main-bastion",
      "name": "Main Bastion",
      "remote_host": "main-bastion.example.com",
      "remote_user": "ipwall",
      "remote_port": 22,
      "remote_script": "/usr/local/bin/ipwall-remote-sync"
    }
  ]
}
```

### Runtime behavior

- Timer invokes host-side `ipscript/firewall_sync.py` on schedule.
- Host computes full desired state from `user_data.yml` each run.
- For each configured target, host sends desired IP list as JSON payload.
- For localhost targets, host invokes the same remote script locally (no SSH transport).
- Calls are per-target with timeout (default `10s`, env `REMOTE_SYNC_TIMEOUT_SECONDS`).
- Failures are isolated: one failed target does not block other targets.
- Results are logged to `remote_sync_results.log` (env `REMOTE_SYNC_LOG_FILE`) including timestamp, requester, target, status, and message.

### Required remote script contract

The remote script should be idempotent and must only modify the `IPWALL_SSH` chain:

```bash
echo '{"chain":"IPWALL_SSH","target_id":"main-bastion","request_id":"req-123","ips":["203.0.113.5"]}' \
  | /usr/local/bin/ipwall-remote-sync
```

Recommended implementation approach:

- Ensure chain exists before updates.
- Build chain from desired list and atomically repoint alias chain.
- Do not alter unrelated chains/rules.

### SSH key and forced-command hardening

On each remote host, create a dedicated key pair and restrict the authorized key with a forced command:

```text
command=\"/usr/local/bin/ipwall-remote-sync-wrapper\",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA... main-ipwall
```

Suggested wrapper behavior:

- Validate expected JSON payload shape and reject anything else.
- Enforce `chain=IPWALL_SSH` regardless of user input.
- Execute only the approved sync script/binary.
- Log invocations for audit.

Also ensure the main server has remote host keys pinned in `known_hosts`, because IPWall uses strict host-key checking.

## Installing the firewall sync job

Use `ipscript/firewall_install.py` as root:

```bash
cd ipscript
sudo python3 firewall_install.py --install
```

Common commands:

```bash
sudo python3 firewall_install.py --install --timer 120
sudo python3 firewall_install.py --install --method cron
sudo python3 firewall_install.py --upgrade
sudo python3 firewall_install.py --enable
sudo python3 firewall_install.py --disable
sudo python3 firewall_install.py --status
sudo python3 firewall_install.py --doctor
sudo python3 firewall_install.py --remove
```

Run `--examples` for full usage examples.

## Operational notes

- Rate limiting is in-process memory only; it resets when the app restarts.
- YAML writes are plain file writes; if multiple app instances share files, add locking/shared storage strategy.
- The app relies on upstream auth and proxy correctness; do not expose directly to the internet without a trusted reverse proxy.

## License

MIT (see `LICENSE`).
