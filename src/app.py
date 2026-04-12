import os
import time
import json
import yaml
import secrets
import ipaddress
from collections import deque
from datetime import datetime, timedelta

from flask import (
    Flask, request, render_template,
    redirect, url_for, flash,
    abort, session
)


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# --------------------------------------------------
# Files
# --------------------------------------------------

USER_DATA_FILE = "user_data.yml"
IP_WHITELIST_FILE = "ip_whitelist.yml"
USER_DATA_META_KEY = "_meta"

# --------------------------------------------------
# Settings
# --------------------------------------------------

IP_EXPIRY_DAYS = 90

UI_CONFIG_FILE = os.environ.get(
    "UI_CONFIG_FILE",
    os.environ.get("UI_CONFIG_PATH", "config/ui_config.json")
)
DEFAULT_UI_CONFIG = {"service_links": [], "ssh_targets": []}

# --------------------------------------------------
# Trusted Proxy Enforcement
# --------------------------------------------------

proxy_cidr = os.environ.get("TRUSTED_PROXY_CIDR", "172.20.0.0/16")

TRUSTED_PROXY_NETWORKS = [
    ipaddress.ip_network(proxy_cidr)
]


def is_trusted_proxy(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in TRUSTED_PROXY_NETWORKS)
    except Exception:
        return False


@app.before_request
def enforce_trusted_proxy():
    if not is_trusted_proxy(request.remote_addr):
        abort(403)


# --------------------------------------------------
# CSRF Protection
# --------------------------------------------------

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def csrf_protect():

    if request.method in ("POST", "PUT", "DELETE"):

        token = session.get("csrf_token")
        form_token = request.form.get("csrf_token")

        if not token or not form_token:
            abort(403)

        if not secrets.compare_digest(token, form_token):
            abort(403)


# --------------------------------------------------
# Rate Limiting
# --------------------------------------------------

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 20

_rate_buckets = {}


def rate_key(identity, scope):
    return f"{scope}:{identity['email']}:{identity['ip']}"


def allow_request(identity, scope):

    now = time.time()

    key = rate_key(identity, scope)

    bucket = _rate_buckets.setdefault(key, deque())

    cutoff = now - RATE_LIMIT_WINDOW_SECONDS

    while bucket and bucket[0] < cutoff:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        return False

    bucket.append(now)
    return True


# --------------------------------------------------
# Identity from oauth2-proxy
# --------------------------------------------------

def get_identity():

    email = request.headers.get("X-Auth-Request-Email")
    groups_raw = request.headers.get("X-Auth-Request-Groups", "")

    ip = request.headers.get("X-Real-Ip") or request.remote_addr

    try:
        ipaddress.ip_address(ip)
    except Exception:
        abort(403)

    if not email:
        abort(403)

    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

    return {
        "email": email,
        "groups": groups,
        "ip": ip
    }


def is_admin(groups):
    return "admin" in groups


# --------------------------------------------------
# UI Config
# --------------------------------------------------

def validate_service_link(entry):

    if not isinstance(entry, dict):
        return None

    link_id = entry.get("id")
    label = entry.get("label")
    url = entry.get("url")

    if not all(isinstance(v, str) and v.strip() for v in (link_id, label, url)):
        return None

    validated = {
        "id": link_id.strip(),
        "label": label.strip(),
        "url": url.strip(),
        "copyable": bool(entry.get("copyable", False))
    }

    icon = entry.get("icon")
    if isinstance(icon, str) and icon.strip():
        normalized_icon = icon.strip()
        lower_icon = normalized_icon.lower()
        if lower_icon.startswith("static/"):
            normalized_icon = normalized_icon[7:]
            lower_icon = normalized_icon.lower()

        if lower_icon.endswith((".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico")):
            validated["icon_static"] = normalized_icon.lstrip("/")
        else:
            validated["icon"] = normalized_icon

    helper_text = entry.get("helper_text")
    if isinstance(helper_text, str) and helper_text.strip():
        validated["helper_text"] = helper_text.strip()

    return validated


def validate_service_group(entry):

    if not isinstance(entry, dict):
        return None

    group_id = entry.get("id")
    heading = entry.get("heading")
    links = entry.get("links")

    if not all(isinstance(v, str) and v.strip() for v in (group_id, heading)):
        return None

    if not isinstance(links, list):
        return None

    validated_links = []
    for link in links:
        validated = validate_service_link(link)
        if validated:
            validated_links.append(validated)

    if not validated_links:
        return None

    validated_group = {
        "id": group_id.strip(),
        "heading": heading.strip(),
        "links": validated_links
    }

    icon = entry.get("icon")
    if isinstance(icon, str) and icon.strip():
        normalized_icon = icon.strip()
        lower_icon = normalized_icon.lower()
        if lower_icon.startswith("static/"):
            normalized_icon = normalized_icon[7:]
            lower_icon = normalized_icon.lower()

        if lower_icon.endswith((".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico")):
            validated_group["icon_static"] = normalized_icon.lstrip("/")
        else:
            validated_group["icon"] = normalized_icon

    return validated_group


def validate_ssh_target(entry):
    if not isinstance(entry, dict):
        return None

    target_id = entry.get("id")
    target_name = entry.get("name")

    if not all(isinstance(v, str) and v.strip() for v in (target_id, target_name)):
        return None

    if not bool(entry.get("enabled", True)):
        return None

    is_localhost = entry.get("localhost") is True
    has_remote_fields = any(
        key in entry
        for key in (
            "remote_host",
            "remote_user",
            "remote_port",
            "remote_script",
            "password",
            "passkey_file",
        )
    )

    if is_localhost and has_remote_fields:
        return None

    if not is_localhost:
        if "localhost" in entry:
            return None

        if not all(
            isinstance(v, str) and v.strip()
            for v in (entry.get("remote_host"), entry.get("remote_user"))
        ):
            return None

        password = entry.get("password")
        if password is not None and (not isinstance(password, str) or not password.strip()):
            return None

        passkey_file = entry.get("passkey_file")
        if passkey_file is not None and (not isinstance(passkey_file, str) or not passkey_file.strip()):
            return None

        port = entry.get("remote_port", 22)
        try:
            port = int(port)
        except Exception:
            return None
        if port < 1 or port > 65535:
            return None

    return {
        "id": target_id.strip(),
        "name": target_name.strip(),
        "localhost": is_localhost,
    }


def load_ui_config(config_path=UI_CONFIG_FILE):
    service_links = []
    ssh_targets = []

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        app.logger.warning(
            "UI config file not found at '%s'; using built-in defaults",
            config_path
        )
        return dict(DEFAULT_UI_CONFIG)
    except json.JSONDecodeError as exc:
        app.logger.warning(
            "UI config file '%s' is invalid JSON (%s); using built-in defaults",
            config_path,
            exc
        )
        return dict(DEFAULT_UI_CONFIG)
    except Exception as exc:
        app.logger.warning(
            "Failed to load UI config file '%s' (%s); using built-in defaults",
            config_path,
            exc
        )
        return dict(DEFAULT_UI_CONFIG)

    raw_targets = raw.get("ssh_targets") if isinstance(raw, dict) else None
    allow_multiple_localhost_targets = bool(raw.get("allow_multiple_localhost_targets", False))
    localhost_seen = False
    if isinstance(raw_targets, list):
        for target in raw_targets:
            validated_target = validate_ssh_target(target)
            if not validated_target:
                continue

            if validated_target["localhost"]:
                if localhost_seen and not allow_multiple_localhost_targets:
                    continue
                localhost_seen = True

            ssh_targets.append({
                "id": validated_target["id"],
                "name": validated_target["name"]
            })

    raw_links = raw.get("service_links") if isinstance(raw, dict) else None
    if not isinstance(raw_links, list):
        return {"service_links": service_links, "ssh_targets": ssh_targets}

    validated_groups = []

    # Preferred schema: grouped links
    for entry in raw_links:
        group = validate_service_group(entry)
        if group:
            validated_groups.append(group)

    if validated_groups:
        return {"service_links": validated_groups, "ssh_targets": ssh_targets}

    # Backward-compatible schema: flat link list
    validated_links = []
    for entry in raw_links:
        validated = validate_service_link(entry)
        if validated:
            validated_links.append(validated)

    if validated_links:
        return {
            "service_links": [
                {
                    "id": "default-group",
                    "heading": "Services",
                    "links": validated_links
                }
            ],
            "ssh_targets": ssh_targets
        }

    app.logger.warning(
        "UI config file '%s' has no valid service links; using default empty links",
        config_path
    )
    return {"service_links": [], "ssh_targets": ssh_targets}


# --------------------------------------------------
# YAML IO
# --------------------------------------------------

def load_yaml(file_path):

    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    return {}


def save_yaml(file_path, data):

    with open(file_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def iter_user_records(data):
    for key, value in data.items():
        if key == USER_DATA_META_KEY:
            continue
        if isinstance(value, dict):
            yield key, value


def mark_desired_state_change(data):
    meta = data.setdefault(USER_DATA_META_KEY, {})
    if not isinstance(meta, dict):
        meta = {}
        data[USER_DATA_META_KEY] = meta

    meta["last_change_at"] = datetime.utcnow().isoformat()
    current_version = meta.get("desired_state_version", 0)
    try:
        current_version = int(current_version)
    except Exception:
        current_version = 0
    meta["desired_state_version"] = current_version + 1


# --------------------------------------------------
# Expired IP Cleanup
# --------------------------------------------------

def cleanup_expired_ips(data):

    cutoff = datetime.utcnow() - timedelta(days=IP_EXPIRY_DAYS)

    changed = False

    for email, user_record in list(iter_user_records(data)):

        ips = user_record.get("ips", [])
        new_list = []

        for entry in ips:

            if isinstance(entry, str):
                new_list.append({
                    "ip": entry,
                    "last_seen": datetime.utcnow().isoformat()
                })
                changed = True
                continue

            try:
                last = datetime.fromisoformat(entry["last_seen"])

                if last >= cutoff:
                    new_list.append(entry)
                else:
                    changed = True

            except Exception:
                changed = True

        if new_list:
            data[email]["ips"] = new_list
        else:
            del data[email]
            changed = True

    return changed


# --------------------------------------------------
# Whitelist Sync
# --------------------------------------------------

def compute_all_valid_ips(data):

    result = set()

    for _, user in iter_user_records(data):

        for entry in user.get("ips", []):

            if isinstance(entry, dict):
                ip = entry.get("ip")

                if ip:
                    result.add(ip)

            elif isinstance(entry, str):
                result.add(entry)

    return sorted(result)


def current_whitelist_ips(data):

    return sorted(
        data.get("http", {})
        .get("middlewares", {})
        .get("middlewares-local-ipwhitelist", {})
        .get("ipWhiteList", {})
        .get("sourceRange", [])
    )


def update_whitelist_if_changed(user_data):

    whitelist = load_yaml(IP_WHITELIST_FILE)

    new_ips = compute_all_valid_ips(user_data)
    current_ips = current_whitelist_ips(whitelist)

    if new_ips != current_ips:

        whitelist.setdefault("http", {}) \
            .setdefault("middlewares", {}) \
            .setdefault("middlewares-local-ipwhitelist", {}) \
            .setdefault("ipWhiteList", {})["sourceRange"] = new_ips

        save_yaml(IP_WHITELIST_FILE, whitelist)


# --------------------------------------------------
# Routes
# --------------------------------------------------

@app.route("/")
def index():

    identity = get_identity()

    data = load_yaml(USER_DATA_FILE)

    if cleanup_expired_ips(data):
        mark_desired_state_change(data)
        save_yaml(USER_DATA_FILE, data)

    update_whitelist_if_changed(data)

    user_record = data.get(identity["email"], {"ips": []})
    user_ips = user_record.get("ips", [])

    current_ip_authorized = any(
        (e.get("ip") == identity["ip"]) if isinstance(e, dict) else (e == identity["ip"])
        for e in user_ips
    )

    # Build admin SSH session view

    active_ssh = []
    now = datetime.utcnow()

    for email, user in data.items():

        for entry in user.get("ips", []):

            for target in entry.get("ssh_targets", []):

                enabled_time = target.get("ssh_enabled_time")
                hours = target.get("ssh_hours", 4)

                expires = None
                status = "Pending"

                if enabled_time:

                    try:

                        start = datetime.fromisoformat(enabled_time)
                        expires = start + timedelta(hours=hours)

                        if expires > now:
                            status = "Active"
                        else:
                            status = "Expired"

                    except Exception:
                        pass

                active_ssh.append({
                    "email": email,
                    "ip": entry.get("ip"),
                    "target_id": target.get("target_id"),
                    "target_name": target.get("target_name", target.get("target_id")),
                    "status": status,
                    "hours": hours,
                    "enabled_time": enabled_time,
                    "expires": expires.isoformat() if expires else None
                })

    ui_config = load_ui_config()

    return render_template(
        "index.html",
        user_data=identity,
        user_ips=user_ips,
        current_ip_authorized=current_ip_authorized,
        expiry_days=IP_EXPIRY_DAYS,
        is_admin=is_admin(identity["groups"]),
        csrf_token=generate_csrf_token(),
        service_links=ui_config["service_links"],
        ssh_targets=ui_config["ssh_targets"],
        active_ssh=active_ssh
    )


# --------------------------------------------------
# Add / Refresh IP
# --------------------------------------------------

@app.route("/add_ip", methods=["POST"])
def add_ip():

    identity = get_identity()

    if not allow_request(identity, "add_ip"):
        flash("Too many requests", "warning")
        return redirect(url_for("index"))

    data = load_yaml(USER_DATA_FILE)

    if cleanup_expired_ips(data):
        mark_desired_state_change(data)
        save_yaml(USER_DATA_FILE, data)

    user = data.setdefault(identity["email"], {"ips": []})

    now = datetime.utcnow().isoformat()

    ssh_target_ids = []
    ssh_hours = 4
    configured_ssh_targets = {
        t["id"]: t["name"]
        for t in load_ui_config().get("ssh_targets", [])
    }

    if is_admin(identity["groups"]):

        raw_target_ids = request.form.getlist("ssh_targets")
        ssh_target_ids = [
            target_id for target_id in raw_target_ids
            if target_id in configured_ssh_targets
        ]

        if ssh_target_ids:
            try:
                ssh_hours = int(request.form.get("ssh_hours", 4))
            except Exception:
                ssh_hours = 4

    # Normalize entries

    normalized = []

    for e in user.get("ips", []):

        if isinstance(e, str):
            normalized.append({"ip": e, "last_seen": now})

        elif isinstance(e, dict) and e.get("ip"):
            normalized.append(e)

    user["ips"] = normalized

    existing = next(
        (e for e in user["ips"] if e.get("ip") == identity["ip"]),
        None
    )
    if existing:
        existing["last_seen"] = now

        if is_admin(identity["groups"]):

            if ssh_target_ids:
                existing["ssh_targets"] = []

                for target_id in ssh_target_ids:
                    # Rule: selecting targets in the admin form grants SSH immediately.
                    # We persist enabledssh=true with a fresh ssh_enabled_time so
                    # compute_desired_target_state() and timer reconciliation both
                    # include the target right away.
                    existing["ssh_targets"].append({
                        "target_id": target_id,
                        "target_name": configured_ssh_targets[target_id],
                        "ssh_hours": ssh_hours,
                        "enabledssh": True,
                        "ssh_enabled_time": now
                    })

            else:

                existing.pop("ssh_targets", None)

        flash("IP refreshed", "success")

    else:

        new_entry = {
            "ip": identity["ip"],
            "last_seen": now
        }

        if ssh_target_ids:

            new_entry["ssh_targets"] = [
                {
                    "target_id": target_id,
                    "target_name": configured_ssh_targets[target_id],
                    "ssh_hours": ssh_hours,
                    # Same immediate-grant rule for first creation.
                    "enabledssh": True,
                    "ssh_enabled_time": now
                }
                for target_id in ssh_target_ids
            ]

        user["ips"].append(new_entry)

        flash("IP added", "success")

    mark_desired_state_change(data)
    save_yaml(USER_DATA_FILE, data)

    update_whitelist_if_changed(data)

    return redirect(url_for("index"))


# --------------------------------------------------
# Remove IP
# --------------------------------------------------

@app.route("/remove_ip", methods=["POST"])
def remove_ip():

    identity = get_identity()

    ip = request.form.get("ip")

    data = load_yaml(USER_DATA_FILE)

    user = data.get(identity["email"])

    if user:

        user["ips"] = [
            e for e in user.get("ips", [])
            if e.get("ip") != ip
        ]

        if not user["ips"]:
            del data[identity["email"]]

    mark_desired_state_change(data)
    save_yaml(USER_DATA_FILE, data)

    update_whitelist_if_changed(data)

    flash("IP removed", "warning")

    return redirect(url_for("index"))


# --------------------------------------------------
# Revoke SSH
# --------------------------------------------------

@app.route("/revoke_ssh", methods=["POST"])
def revoke_ssh():

    identity = get_identity()

    if not is_admin(identity["groups"]):
        abort(403)

    ip = request.form.get("ip")
    target_id = request.form.get("target_id")

    data = load_yaml(USER_DATA_FILE)

    for _, user in iter_user_records(data):

        for entry in user.get("ips", []):

            if entry.get("ip") == ip:
                current_targets = entry.get("ssh_targets", [])
                if not isinstance(current_targets, list):
                    continue

                entry["ssh_targets"] = [
                    target for target in current_targets
                    if target.get("target_id") != target_id
                ]

                if not entry["ssh_targets"]:
                    entry.pop("ssh_targets", None)

    mark_desired_state_change(data)
    save_yaml(USER_DATA_FILE, data)

    flash("SSH access revoked", "warning")

    return redirect(url_for("index"))


# --------------------------------------------------
# Clear all users
# --------------------------------------------------

@app.route("/clear_all_users", methods=["POST"])
def clear_all_users():

    identity = get_identity()

    if not is_admin(identity["groups"]):
        abort(403)

    confirm = request.form.get("confirm")

    if confirm != "YES":
        flash("Confirmation failed", "warning")
        return redirect(url_for("index"))

    data = {}
    mark_desired_state_change(data)
    save_yaml(USER_DATA_FILE, data)

    whitelist = load_yaml(IP_WHITELIST_FILE)

    whitelist.setdefault("http", {}) \
        .setdefault("middlewares", {}) \
        .setdefault("middlewares-local-ipwhitelist", {}) \
        .setdefault("ipWhiteList", {})["sourceRange"] = []

    save_yaml(IP_WHITELIST_FILE, whitelist)

    flash("All user data cleared", "danger")

    return redirect(url_for("index"))


# --------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
