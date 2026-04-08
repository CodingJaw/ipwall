# IPWall

IPWall is a lightweight Flask app for self-service IP allowlisting behind an auth proxy (such as `oauth2-proxy`) and reverse proxy middleware (such as Traefik IP whitelisting).

Users can add/refresh their current IP, and admins can request temporary SSH access per IP with automatic expiry handled by a companion firewall sync script.

## What it does

- Authenticated users can register their current client IP.
- Registered IPs are timestamped and automatically expired after inactivity.
- The app continuously syncs all valid IPs into a whitelist YAML file for proxy enforcement.
- Admin users can mark an IP for temporary SSH access (1h, 2h, 4h, 8h, 12h, 24h).
- A separate firewall sync script applies SSH access to an `iptables` chain and revokes expired SSH grants.

## Repository layout

- `src/app.py` — Flask web app and YAML syncing logic.
- `src/templates/` — UI templates.
- `src/static/` — Bootstrap assets and icons.
- `ipscript/firewall_sync.py` — deterministic SSH firewall rule reconciler.
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
  -e UI_CONFIG_PATH='/app/config/ui_config.json' \
  -v $(pwd)/config/ui_config.json:/app/config/ui_config.json:ro \
  ipwall
```

The provided `Dockerfile` uses `python:3.11-alpine`, copies the repo into `/app`, installs requirements, and starts `python src/app.py`.

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
| `UI_CONFIG_PATH` | `config/ui_config.json` | Path to JSON UI config containing dashboard service links |

## UI service links config

The dashboard "Services" section is loaded from JSON at `UI_CONFIG_PATH` (default `config/ui_config.json`).

Initialize local config from the template:

```bash
cp config/ui_config.example.json config/ui_config.json
```

`service_links` is an array. Each row requires:

- `id` (string)
- `label` (string)
- `url` (string)

Optional fields:

- `copyable` (boolean) — render "Copy Link to Clipboard" button when `true`.
- `helper_text` (string) — render descriptive helper text above the displayed URL.

Malformed rows are ignored. If the file is missing/invalid or all rows are malformed, the app will render no service links.

Example:

```json
{
  "service_links": [
    {
      "id": "primary-app",
      "label": "Open APP",
      "url": "https://sub.example.com"
    },
    {
      "id": "apps-or-browser",
      "label": "Apps or Browser",
      "url": "https://sub2.example.com",
      "copyable": true,
      "helper_text": "Apps must use this link to connect"
    }
  ]
}
```

### Docker deployment notes

- This repo ships `config/ui_config.example.json` as a template.
- Create your real config as `config/ui_config.json` (gitignored) so future pulls do not overwrite it.
- To customize links without rebuilding, bind mount your config file and set `UI_CONFIG_PATH` if you use a different location.
- Recommended mount: `-v /path/on/host/ui_config.json:/app/config/ui_config.json:ro`.

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

## SSH firewall sync

`ipscript/firewall_sync.py`:

- Reads `USER_DATA_FILE` (default `/srv/docker-traefik/appdata/ipwall/user_data.yml`).
- Ensures custom chain `IPWALL_SSH` exists and is linked from `INPUT` for TCP/22.
- Rebuilds chain from scratch each run based on active `ssh: true` entries.
- Marks first activation (`enabledssh`, `ssh_enabled_time`) and logs to `/var/log/ipwall_ssh_audit.log`.
- Auto-revokes expired SSH grants (`ssh_hours`, default 4h).

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
