#!/usr/bin/env python3

import argparse
import fcntl
import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import yaml

USER_DATA_FILE = os.environ.get("USER_DATA_FILE", "user_data.yml")
LOCAL_TARGET_ID = os.environ.get("LOCAL_TARGET_ID", "localhost")
SSH_PORT = os.environ.get("SSH_PORT", "22")
LOCAL_CHAIN = os.environ.get("LOCAL_CHAIN", "IPWALL_LOCAL_SSH")
STATE_FILE = os.environ.get("IPWALL_LOCAL_STATE_FILE", "/var/lib/ipwall/local_sync_state.json")
LOCK_FILE = os.environ.get("IPWALL_LOCAL_LOCK_FILE", "/var/lock/ipwall-local-sync.lock")


def parse_args():
    parser = argparse.ArgumentParser(description="Apply local SSH iptables state from user_data.yml")
    parser.add_argument("--force", action="store_true", help="apply iptables even if desired_state metadata is unchanged")
    parser.add_argument("--dry-run", action="store_true", help="print planned changes without running iptables")
    return parser.parse_args()


def utc_now():
    return datetime.now(timezone.utc)


def run_cmd(cmd, check=True, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(" ".join(cmd))
        print("[dry-run]", " ".join(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    completed = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if check and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(cmd)} :: {stderr}")
    return completed


def load_yaml(path):
    if not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    if not isinstance(loaded, dict):
        raise RuntimeError(f"YAML root must be object: {path}")

    return loaded


def parse_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def target_state_active(target, now_utc):
    if not isinstance(target, dict):
        return False

    if not bool(target.get("enabledssh")):
        return False

    enabled_time = parse_datetime(target.get("ssh_enabled_time"))
    if enabled_time is None:
        return True

    try:
        ssh_hours = int(target.get("ssh_hours", 4))
    except Exception:
        ssh_hours = 4

    if ssh_hours < 1:
        ssh_hours = 1

    expires_at = enabled_time.timestamp() + (ssh_hours * 3600)
    return now_utc.timestamp() <= expires_at


def desired_local_ips(user_data, local_target_id):
    now_utc = utc_now()
    desired = set()

    for user_key, user in user_data.items():
        if user_key == "_meta" or not isinstance(user, dict):
            continue

        for entry in user.get("ips", []):
            if not isinstance(entry, dict):
                continue

            raw_ip = entry.get("ip")
            try:
                ip_value = str(ipaddress.ip_address(raw_ip))
            except Exception:
                continue

            ssh_targets = entry.get("ssh_targets", [])
            if not isinstance(ssh_targets, list):
                continue

            for target in ssh_targets:
                if not target_state_active(target, now_utc):
                    continue

                target_id = target.get("target_id")
                if not isinstance(target_id, str):
                    continue

                if target_id.strip() == local_target_id:
                    desired.add(ip_value)

    return sorted(desired)


def chain_exists(chain):
    completed = run_cmd(["iptables", "-L", chain], check=False)
    return completed.returncode == 0


def ensure_chain_and_jump(chain, dry_run=False, command_log=None):
    if not chain_exists(chain):
        run_cmd(["iptables", "-N", chain], dry_run=dry_run, command_log=command_log)

    check_jump = run_cmd(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", SSH_PORT, "-j", chain],
        check=False,
        dry_run=dry_run,
    )
    if check_jump.returncode != 0:
        run_cmd(
            ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", SSH_PORT, "-j", chain],
            dry_run=dry_run,
            command_log=command_log,
        )


def get_applied_ips(chain):
    completed = run_cmd(["iptables", "-S", chain], check=False)
    if completed.returncode != 0:
        return []

    applied = set()
    for line in (completed.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "-A" or parts[1] != chain:
            continue
        if "-j" not in parts:
            continue
        jump_target = parts[parts.index("-j") + 1]
        if jump_target != "ACCEPT" or "-s" not in parts:
            continue
        source = parts[parts.index("-s") + 1]
        applied.add(source.split("/")[0])

    return sorted(applied)


def ensure_return_rule(chain, dry_run=False, command_log=None):
    check_return = run_cmd(["iptables", "-C", chain, "-j", "RETURN"], check=False, dry_run=dry_run)
    if check_return.returncode != 0:
        run_cmd(["iptables", "-A", chain, "-j", "RETURN"], dry_run=dry_run, command_log=command_log)


def remove_ip_rule(chain, ip_value, dry_run=False, command_log=None):
    run_cmd(
        [
            "iptables",
            "-D",
            chain,
            "-p",
            "tcp",
            "-s",
            ip_value,
            "--dport",
            SSH_PORT,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        dry_run=dry_run,
        command_log=command_log,
    )


def add_ip_rule(chain, ip_value, dry_run=False, command_log=None):
    run_cmd(
        [
            "iptables",
            "-I",
            chain,
            "1",
            "-p",
            "tcp",
            "-s",
            ip_value,
            "--dport",
            SSH_PORT,
            "-m",
            "conntrack",
            "--ctstate",
            "NEW,ESTABLISHED",
            "-j",
            "ACCEPT",
        ],
        dry_run=dry_run,
        command_log=command_log,
    )


def reconcile_chain(chain, desired_ips, dry_run=False):
    command_log = []
    ensure_chain_and_jump(chain, dry_run=dry_run, command_log=command_log)

    applied_ips = get_applied_ips(chain)
    applied_set = set(applied_ips)
    desired_set = set(desired_ips)

    to_remove = sorted(applied_set - desired_set)
    to_add = sorted(desired_set - applied_set)

    for ip_value in to_remove:
        remove_ip_rule(chain, ip_value, dry_run=dry_run, command_log=command_log)

    for ip_value in to_add:
        add_ip_rule(chain, ip_value, dry_run=dry_run, command_log=command_log)

    ensure_return_rule(chain, dry_run=dry_run, command_log=command_log)

    return {
        "desired": desired_ips,
        "before": applied_ips,
        "removed": to_remove,
        "added": to_add,
        "planned_commands": command_log,
    }


def ensure_parent_dir(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def state_fingerprint(user_data_path, data):
    meta = data.get("_meta", {}) if isinstance(data, dict) else {}
    if not isinstance(meta, dict):
        meta = {}

    try:
        file_mtime = os.path.getmtime(user_data_path)
    except OSError:
        file_mtime = 0

    return {
        "desired_state_version": meta.get("desired_state_version"),
        "last_change_at": meta.get("last_change_at"),
        "user_data_mtime": file_mtime,
    }


def load_last_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            return loaded
    except Exception:
        return {}
    return {}


def save_state(path, fingerprint, result):
    ensure_parent_dir(path)
    payload = {
        "last_run_at": utc_now().isoformat(),
        "fingerprint": fingerprint,
        "result": result,
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))


def acquire_lock(path):
    ensure_parent_dir(path)
    lock = open(path, "w", encoding="utf-8")
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def main():
    args = parse_args()

    if os.geteuid() != 0:
        print("ERROR: local firewall sync must run as root", file=sys.stderr)
        return 1

    lock = acquire_lock(LOCK_FILE)
    try:
        user_data = load_yaml(USER_DATA_FILE)
        desired_ips = desired_local_ips(user_data, LOCAL_TARGET_ID)
        fingerprint = state_fingerprint(USER_DATA_FILE, user_data)
        previous = load_last_state(STATE_FILE)
        previous_fingerprint = previous.get("fingerprint") if isinstance(previous, dict) else {}

        if (not args.force) and (not args.dry_run) and fingerprint == previous_fingerprint:
            print(json.dumps({
                "ok": True,
                "skipped": True,
                "reason": "user_data unchanged",
                "fingerprint": fingerprint,
                "desired_ips": desired_ips,
            }, separators=(",", ":")))
            return 0

        result = reconcile_chain(LOCAL_CHAIN, desired_ips, dry_run=args.dry_run)
        output = {
            "ok": True,
            "skipped": False,
            "dry_run": bool(args.dry_run),
            "fingerprint": fingerprint,
            "chain": LOCAL_CHAIN,
            **result,
        }
        if not args.dry_run:
            save_state(STATE_FILE, fingerprint, output)
        print(json.dumps(output, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        return 1
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
