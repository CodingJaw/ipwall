#!/usr/bin/env python3

import subprocess
import yaml
from datetime import datetime, timedelta, timezone

# --------------------------------------------------
# Configuration
# --------------------------------------------------

USER_DATA_FILE = "/srv/docker-traefik/appdata/ipwall/user_data.yml"

SSH_PORT = "22"

CHAIN = "IPWALL_SSH"

AUDIT_LOG = "/var/log/ipwall_ssh_audit.log"

DEFAULT_SSH_HOURS = 4


# --------------------------------------------------
# Utility
# --------------------------------------------------

def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def utcnow():
    return datetime.now(timezone.utc)


# --------------------------------------------------
# Ensure firewall chain exists
# --------------------------------------------------

def ensure_chain():

    result = subprocess.run(
        ["iptables", "-L", CHAIN],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if result.returncode != 0:

        run(["iptables", "-N", CHAIN])

        run([
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            SSH_PORT,
            "-j",
            CHAIN
        ])


# --------------------------------------------------
# Logging
# --------------------------------------------------

def log_event(event, email, ip, hours=None):

    ts = utcnow().isoformat()

    line = f"{ts} {event} email={email} ip={ip}"

    if hours:
        line += f" duration={hours}h"

    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# --------------------------------------------------
# YAML helpers
# --------------------------------------------------

def load_yaml():

    try:
        with open(USER_DATA_FILE) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def save_yaml(data):

    try:
        with open(USER_DATA_FILE, "w") as f:
            yaml.safe_dump(data, f, sort_keys=False)
    except Exception:
        pass


# --------------------------------------------------
# SSH expiration
# --------------------------------------------------

def ssh_expired(entry):

    if "ssh_enabled_time" not in entry:
        return False

    hours = entry.get("ssh_hours", DEFAULT_SSH_HOURS)

    try:

        start = datetime.fromisoformat(entry["ssh_enabled_time"])

        expire = start + timedelta(hours=hours)

        return utcnow() > expire

    except Exception:

        return False


# --------------------------------------------------
# Rebuild firewall chain deterministically
# --------------------------------------------------

def rebuild_chain(allowed_ips):

    # Flush existing rules
    run(["iptables", "-F", CHAIN])

    # Add allowed SSH IPs
    for ip in sorted(allowed_ips):

        run([
            "iptables",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "-s",
            ip,
            "--dport",
            SSH_PORT,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT"
        ])

    # Always finish with RETURN
    run(["iptables", "-A", CHAIN, "-j", "RETURN"])


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    ensure_chain()

    data = load_yaml()

    allowed_ips = set()

    yaml_changed = False

    for email, user in data.items():

        for entry in user.get("ips", []):

            ip = entry.get("ip")

            if not ip:
                continue

            # Only process ssh:true entries
            if entry.get("ssh") is not True:
                continue

            # Check expiration
            if ssh_expired(entry):

                log_event("EXPIRE", email, ip)

                entry.pop("ssh", None)
                entry.pop("enabledssh", None)
                entry.pop("ssh_hours", None)
                entry.pop("ssh_enabled_time", None)

                yaml_changed = True

                continue

            allowed_ips.add(ip)

            # First activation
            if not entry.get("enabledssh"):

                entry["enabledssh"] = True
                entry["ssh_enabled_time"] = utcnow().isoformat()

                hours = entry.get("ssh_hours", DEFAULT_SSH_HOURS)

                log_event("ENABLE", email, ip, hours)

                yaml_changed = True

    # Rebuild firewall rules
    rebuild_chain(allowed_ips)

    if yaml_changed:
        save_yaml(data)


# --------------------------------------------------

if __name__ == "__main__":
    main()
