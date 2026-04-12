#!/usr/bin/env python3

import ipaddress
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone

import yaml

if __package__ in (None, ""):
    sys.path.append(os.path.dirname(__file__))

from sync_schema import normalize_ip_list, parse_remote_response

UI_CONFIG_FILE = os.environ.get(
    "UI_CONFIG_FILE",
    os.environ.get("UI_CONFIG_PATH", "config/ui_config.json"),
)
USER_DATA_FILE = os.environ.get("USER_DATA_FILE", "user_data.yml")
REMOTE_SYNC_LOG_FILE = os.environ.get("REMOTE_SYNC_LOG_FILE", "remote_sync_results.log")
REMOTE_SYNC_TIMEOUT_SECONDS = int(os.environ.get("REMOTE_SYNC_TIMEOUT_SECONDS", "10"))
REMOTE_SYNC_SCRIPT = os.environ.get("REMOTE_SYNC_SCRIPT", "/usr/local/bin/ipwall-remote-sync")
REMOTE_SYNC_CHAIN = os.environ.get("REMOTE_SYNC_CHAIN", "IPWALL_SSH")
REQUESTER_EMAIL = os.environ.get("SYNC_REQUESTER_EMAIL", "system@ipwall.local")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def parse_sync_target(target):
    if not isinstance(target, dict):
        return None

    target_id = target.get("id")
    if not isinstance(target_id, str) or not target_id.strip():
        return None

    if not bool(target.get("enabled", True)):
        return None

    is_localhost = target.get("localhost") is True
    has_remote_fields = any(
        key in target for key in ("remote_host", "remote_user", "remote_port", "remote_script")
    )

    if is_localhost:
        if has_remote_fields:
            return None
        return {
            "id": target_id.strip(),
            "type": "local",
            "script": REMOTE_SYNC_SCRIPT,
        }

    if "localhost" in target:
        return None

    host = target.get("remote_host")
    user = target.get("remote_user")
    if not all(isinstance(v, str) and v.strip() for v in (host, user)):
        return None

    try:
        port = int(target.get("remote_port", 22))
    except Exception:
        return None

    if port < 1 or port > 65535:
        return None

    return {
        "id": target_id.strip(),
        "type": "remote",
        "host": host.strip(),
        "user": user.strip(),
        "port": port,
        "script": str(target.get("remote_script", REMOTE_SYNC_SCRIPT)).strip() or REMOTE_SYNC_SCRIPT,
    }


def load_target_map(path=UI_CONFIG_FILE):
    target_map = {}
    raw = load_json(path)
    allow_multiple_localhost_targets = bool(raw.get("allow_multiple_localhost_targets", False))
    localhost_seen = False

    for target in raw.get("ssh_targets", []):
        parsed_target = parse_sync_target(target)
        if not parsed_target:
            continue

        if parsed_target["type"] == "local":
            if localhost_seen and not allow_multiple_localhost_targets:
                continue
            localhost_seen = True

        target_map[parsed_target["id"]] = parsed_target

    return target_map


def parse_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def target_state_active(target, now):
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

    expiry = enabled_time.timestamp() + (ssh_hours * 3600)
    return now.timestamp() <= expiry


def compute_desired_target_state(user_data):
    now = datetime.now(timezone.utc)
    desired = {}

    if not isinstance(user_data, dict):
        return desired

    for user in user_data.values():
        if not isinstance(user, dict):
            continue

        for entry in user.get("ips", []):
            if not isinstance(entry, dict):
                continue

            ip = entry.get("ip")
            try:
                normalized_ip = str(ipaddress.ip_address(ip))
            except Exception:
                continue

            ssh_targets = entry.get("ssh_targets", [])
            if not isinstance(ssh_targets, list):
                continue

            for ssh_target in ssh_targets:
                if not target_state_active(ssh_target, now):
                    continue

                target_id = ssh_target.get("target_id")
                if not isinstance(target_id, str) or not target_id.strip():
                    continue

                desired.setdefault(target_id.strip(), set()).add(normalized_ip)

    return {target_id: sorted(ips) for target_id, ips in sorted(desired.items())}


def write_result_log(result):
    line = (
        f"{result['timestamp']} correlation_id={result['correlation_id']} "
        f"target_id={result['target_id']} expected_count={result['expected_count']} "
        f"requester={result['requester_email']} "
        f"status={result['status']} message={result['message']}"
    )

    try:
        with open(REMOTE_SYNC_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run_target_state(requester_email, target_id, ips, target, timeout_seconds, correlation_id):
    expected_count = len(ips)
    request_id = str(uuid.uuid4())
    base = {
        "timestamp": utc_now_iso(),
        "correlation_id": correlation_id,
        "target_id": target_id,
        "expected_count": expected_count,
        "requester_email": requester_email,
    }

    payload = {
        "chain": REMOTE_SYNC_CHAIN,
        "ips": ips,
        "request_id": request_id,
        "target_id": target_id,
    }

    if target.get("type") == "local":
        cmd = [target["script"]]
    else:
        cmd = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"ConnectTimeout={timeout_seconds}",
            "-p",
            str(target["port"]),
            f"{target['user']}@{target['host']}",
            target["script"],
        ]

    try:
        completed = subprocess.run(
            cmd,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        stderr = (completed.stderr or "").strip()
        response, response_error = parse_remote_response(completed.stdout)

        if response and response.get("applied_ips") != ips:
            response_error = (
                "remote applied_ips mismatch "
                f"expected={ips} got={response.get('applied_ips')}"
            )

        remote_ok = bool(response and response.get("ok"))

        if completed.returncode == 0 and remote_ok and response_error is None:
            result = {
                **base,
                "status": "success",
                "message": "update applied and verified",
            }
        else:
            error_parts = []
            if completed.returncode != 0:
                error_parts.append(f"command exited {completed.returncode}")
            if response_error:
                error_parts.append(response_error)
            if response and not remote_ok:
                errors = response.get("errors", [])
                if errors:
                    error_parts.append(f"remote errors={errors}")
            if stderr:
                error_parts.append(f"stderr={stderr[:300]}")

            result = {
                **base,
                "status": "failure",
                "message": "; ".join(error_parts)[:700] or "command failed",
            }

    except subprocess.TimeoutExpired:
        result = {
            **base,
            "status": "failure",
            "message": "command timed out",
        }
    except Exception as exc:
        result = {
            **base,
            "status": "failure",
            "message": f"command error: {exc}",
        }

    write_result_log(result)
    return result


def sync_all_target_states(user_data, requester_email, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS, correlation_id=None):
    correlation_id = correlation_id or str(uuid.uuid4())
    targets = load_target_map()
    desired_state = compute_desired_target_state(user_data)
    results = []

    for target_id in sorted(targets):
        ips = normalize_ip_list(desired_state.get(target_id, []))
        results.append(
            run_target_state(
                requester_email=requester_email,
                target_id=target_id,
                ips=ips,
                target=targets[target_id],
                timeout_seconds=timeout_seconds,
                correlation_id=correlation_id,
            )
        )

    successes = sum(1 for r in results if r["status"] == "success")

    return {
        "correlation_id": correlation_id,
        "requested": len(results),
        "succeeded": successes,
        "failed": len(results) - successes,
        "results": results,
    }


def main():
    user_data = load_yaml(USER_DATA_FILE)
    summary = sync_all_target_states(user_data=user_data, requester_email=REQUESTER_EMAIL)
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
