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

# --------------------------------------------------
# Settings
# --------------------------------------------------

IP_EXPIRY_DAYS = 90

UI_CONFIG_PATH = os.environ.get("UI_CONFIG_PATH", "config/ui_config.json")

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

    return {
        "id": group_id.strip(),
        "heading": heading.strip(),
        "links": validated_links
    }


def load_ui_config(config_path=UI_CONFIG_PATH):
    service_links = []

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {"service_links": service_links}

    raw_links = raw.get("service_links") if isinstance(raw, dict) else None
    if not isinstance(raw_links, list):
        return {"service_links": service_links}

    validated_groups = []

    # Preferred schema: grouped links
    for entry in raw_links:
        group = validate_service_group(entry)
        if group:
            validated_groups.append(group)

    if validated_groups:
        return {"service_links": validated_groups}

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
            ]
        }

    return {"service_links": service_links}


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


# --------------------------------------------------
# Expired IP Cleanup
# --------------------------------------------------

def cleanup_expired_ips(data):

    cutoff = datetime.utcnow() - timedelta(days=IP_EXPIRY_DAYS)

    changed = False

    for email in list(data.keys()):

        ips = data[email].get("ips", [])
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

    for user in data.values():

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

            if entry.get("ssh"):

                enabled_time = entry.get("ssh_enabled_time")
                hours = entry.get("ssh_hours", 4)

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

    cleanup_expired_ips(data)

    user = data.setdefault(identity["email"], {"ips": []})

    now = datetime.utcnow().isoformat()

    ssh_requested = False
    ssh_hours = 4

    if is_admin(identity["groups"]):

        if request.form.get("ssh_enable") == "1":
            ssh_requested = True

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

            if ssh_requested:

                existing["ssh"] = True
                existing["ssh_hours"] = ssh_hours

                if "enabledssh" not in existing:
                    existing["enabledssh"] = False

            else:

                existing.pop("ssh", None)
                existing.pop("enabledssh", None)
                existing.pop("ssh_hours", None)
                existing.pop("ssh_enabled_time", None)

        flash("IP refreshed", "success")

    else:

        new_entry = {
            "ip": identity["ip"],
            "last_seen": now
        }

        if ssh_requested:

            new_entry["ssh"] = True
            new_entry["ssh_hours"] = ssh_hours
            new_entry["enabledssh"] = False

        user["ips"].append(new_entry)

        flash("IP added", "success")

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

    data = load_yaml(USER_DATA_FILE)

    for user in data.values():

        for entry in user.get("ips", []):

            if entry.get("ip") == ip:

                entry.pop("ssh", None)
                entry.pop("enabledssh", None)
                entry.pop("ssh_hours", None)
                entry.pop("ssh_enabled_time", None)

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

    save_yaml(USER_DATA_FILE, {})

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
