#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import yaml

USER_DATA_FILE = os.environ.get("USER_DATA_FILE", "user_data.yml")
UI_CONFIG_FILE = os.environ.get("UI_CONFIG_FILE", "config/ui_config.json")
DEFAULT_REMOTE_SCRIPT = os.environ.get("IPWALL_REMOTE_SCRIPT", "/usr/local/bin/ipwall-firewall-sync")
DEFAULT_CHAIN = os.environ.get("IPWALL_REMOTE_CHAIN", "IPWALL_REMOTE_SSH")
SYNC_TIMEOUT_SECONDS = int(os.environ.get("REMOTE_SYNC_TIMEOUT_SECONDS", "10"))


class SyncError(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Compute per-target SSH IP state from user_data + ui_config and send desired IPs "
            "to each target remote script"
        ),
    )
    parser.add_argument("--user-data", default=USER_DATA_FILE, help="path to user_data.yml")
    parser.add_argument("--ui-config", default=UI_CONFIG_FILE, help="path to ui_config.json")
    parser.add_argument("--chain", default=DEFAULT_CHAIN, help="iptables chain sent in payload")
    parser.add_argument("--request-id", default=f"req-{uuid.uuid4()}", help="request identifier")
    parser.add_argument("--target-id", action="append", default=[], help="only sync this target id (repeatable)")
    parser.add_argument("--dry-run", action="store_true", help="compute and print commands/payloads without executing")
    parser.add_argument("--timeout", type=int, default=SYNC_TIMEOUT_SECONDS, help="per-target command timeout (seconds)")
    return parser.parse_args()


def load_yaml(path):
    if not os.path.exists(path):
        raise SyncError(f"user data file not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    if not isinstance(loaded, dict):
        raise SyncError(f"YAML root must be object: {path}")

    return loaded


def load_json(path):
    if not os.path.exists(path):
        raise SyncError(f"ui config file not found: {path}")

    with open(path, "r", encoding="utf-8") as handle:
        loaded = json.load(handle)

    if not isinstance(loaded, dict):
        raise SyncError(f"JSON root must be object: {path}")

    return loaded


def parse_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def normalize_ip(value):
    return str(ipaddress.ip_address(value))


def normalize_target(target):
    if not isinstance(target, dict):
        return None

    target_id = target.get("id")
    if not isinstance(target_id, str) or not target_id.strip():
        return None

    normalized = {
        "id": target_id.strip(),
        "name": target.get("name") or target_id.strip(),
        "enabled": bool(target.get("enabled", True)),
        "localhost": bool(target.get("localhost", False)),
        "remote_script": target.get("remote_script") or DEFAULT_REMOTE_SCRIPT,
        "remote_host": target.get("remote_host"),
        "remote_user": target.get("remote_user"),
        "remote_port": int(target.get("remote_port", 22)),
        "password": target.get("password"),
        "passkey_file": target.get("passkey_file"),
    }

    if normalized["localhost"]:
        normalized["transport"] = "local"
    else:
        if not normalized["remote_host"] or not normalized["remote_user"]:
            return None
        normalized["transport"] = "ssh"

    return normalized


def extract_targets(ui_config, only_ids):
    raw_targets = ui_config.get("ssh_targets", [])
    if not isinstance(raw_targets, list):
        return []

    targets = []
    for raw_target in raw_targets:
        normalized = normalize_target(raw_target)
        if normalized is None:
            continue

        if only_ids and normalized["id"] not in only_ids:
            continue

        if not normalized["enabled"]:
            continue

        targets.append(normalized)

    return targets


def classify_and_map_grants(user_data):
    now = datetime.now(timezone.utc)
    desired_by_target = defaultdict(set)
    grant_records = []

    for user_key, user in user_data.items():
        if user_key == "_meta" or not isinstance(user, dict):
            continue

        for entry in user.get("ips", []):
            if not isinstance(entry, dict):
                continue

            ip_raw = entry.get("ip")
            try:
                ip_value = normalize_ip(ip_raw)
            except Exception:
                continue

            for grant in entry.get("ssh_targets", []):
                if not isinstance(grant, dict):
                    continue

                target_id = grant.get("target_id")
                if not isinstance(target_id, str) or not target_id.strip():
                    continue

                status = "active"
                reason = None

                if not bool(grant.get("enabledssh", False)):
                    status = "revoked"
                    reason = "enabledssh=false"
                else:
                    enabled_time = parse_datetime(grant.get("ssh_enabled_time"))
                    try:
                        ssh_hours = int(grant.get("ssh_hours", 4))
                    except Exception:
                        ssh_hours = 4

                    if ssh_hours < 1:
                        ssh_hours = 1

                    if enabled_time is None:
                        status = "active"
                    else:
                        expires_at = enabled_time + timedelta(hours=ssh_hours)
                        if expires_at <= now:
                            status = "expired"
                            reason = f"expired_at={expires_at.isoformat()}"

                if status == "active":
                    desired_by_target[target_id.strip()].add(ip_value)

                grant_records.append(
                    {
                        "user": user_key,
                        "ip": ip_value,
                        "target_id": target_id.strip(),
                        "status": status,
                        "reason": reason,
                    },
                )

    return {k: sorted(v) for k, v in desired_by_target.items()}, grant_records


def run_target_sync(target, payload, timeout_seconds, dry_run=False):
    payload_json = json.dumps(payload, separators=(",", ":"))

    if target["transport"] == "local":
        cmd = [target["remote_script"]]
    else:
        cmd = ["ssh"]
        if target.get("password"):
            cmd = ["sshpass", "-p", target["password"], "ssh"]
            cmd.extend(["-o", "BatchMode=no"])
        else:
            cmd.extend(["-o", "BatchMode=yes"])

        cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
        if target.get("passkey_file"):
            cmd.extend(["-i", target["passkey_file"]])
        cmd.extend(["-p", str(target["remote_port"])])
        cmd.append(f"{target['remote_user']}@{target['remote_host']}")
        cmd.append(target["remote_script"])

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "command": cmd,
            "payload": payload,
            "stdout": "",
            "stderr": "",
            "returncode": 0,
        }

    completed = subprocess.run(
        cmd,
        input=payload_json,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )

    response_obj = None
    stdout_trimmed = (completed.stdout or "").strip()
    if stdout_trimmed:
        try:
            response_obj = json.loads(stdout_trimmed)
        except Exception:
            response_obj = None

    ok = completed.returncode == 0
    if isinstance(response_obj, dict):
        ok = ok and bool(response_obj.get("ok", True))

    return {
        "ok": ok,
        "dry_run": False,
        "command": cmd,
        "payload": payload,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
        "response": response_obj,
    }


def main():
    args = parse_args()

    user_data = load_yaml(args.user_data)
    ui_config = load_json(args.ui_config)

    desired_by_target, grant_records = classify_and_map_grants(user_data)
    targets = extract_targets(ui_config, set(args.target_id))

    results = []
    for target in targets:
        payload = {
            "chain": args.chain,
            "target_id": target["id"],
            "request_id": args.request_id,
            "ips": desired_by_target.get(target["id"], []),
        }

        target_result = run_target_sync(target, payload, timeout_seconds=args.timeout, dry_run=args.dry_run)
        results.append(
            {
                "target_id": target["id"],
                "target_name": target["name"],
                "transport": target["transport"],
                "desired_ips": payload["ips"],
                "result": target_result,
            },
        )

    summary = {
        "ok": all(item["result"]["ok"] for item in results) if results else True,
        "request_id": args.request_id,
        "chain": args.chain,
        "user_data_file": args.user_data,
        "ui_config_file": args.ui_config,
        "targets_processed": len(results),
        "grants_total": len(grant_records),
        "grants_active": sum(1 for record in grant_records if record["status"] == "active"),
        "grants_expired": sum(1 for record in grant_records if record["status"] == "expired"),
        "grants_revoked": sum(1 for record in grant_records if record["status"] == "revoked"),
        "grant_records": grant_records,
        "results": results,
    }

    print(json.dumps(summary, separators=(",", ":")))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
