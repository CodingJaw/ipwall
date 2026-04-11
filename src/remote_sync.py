import ipaddress
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone


UI_CONFIG_FILE = os.environ.get(
    "UI_CONFIG_FILE",
    os.environ.get("UI_CONFIG_PATH", "config/ui_config.json")
)
REMOTE_SYNC_LOG_FILE = os.environ.get("REMOTE_SYNC_LOG_FILE", "remote_sync_results.log")
REMOTE_SYNC_TIMEOUT_SECONDS = int(os.environ.get("REMOTE_SYNC_TIMEOUT_SECONDS", "10"))
REMOTE_SYNC_SCRIPT = os.environ.get("REMOTE_SYNC_SCRIPT", "/usr/local/bin/ipwall-remote-sync")
REMOTE_SYNC_CHAIN = os.environ.get("REMOTE_SYNC_CHAIN", "IPWALL_SSH")


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _load_config(path=UI_CONFIG_FILE):
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def load_target_map(path=UI_CONFIG_FILE):
    target_map = {}
    raw = _load_config(path)

    for target in raw.get("ssh_targets", []):
        if not isinstance(target, dict):
            continue

        if not bool(target.get("enabled", True)):
            continue

        target_id = target.get("id")
        host = target.get("remote_host")
        user = target.get("remote_user")
        port = target.get("remote_port", 22)

        if not all(isinstance(v, str) and v.strip() for v in (target_id, host, user)):
            continue

        try:
            port = int(port)
        except Exception:
            continue

        if port < 1 or port > 65535:
            continue

        target_map[target_id.strip()] = {
            "host": host.strip(),
            "user": user.strip(),
            "port": port,
            "script": str(target.get("remote_script", REMOTE_SYNC_SCRIPT)).strip() or REMOTE_SYNC_SCRIPT,
        }

    return target_map


def _write_result_log(result):
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


def _parse_datetime(value):
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _target_state_active(target, now):
    if not isinstance(target, dict):
        return False

    if not bool(target.get("enabledssh")):
        return False

    enabled_time = _parse_datetime(target.get("ssh_enabled_time"))
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
                if not _target_state_active(ssh_target, now):
                    continue

                target_id = ssh_target.get("target_id")
                if not isinstance(target_id, str) or not target_id.strip():
                    continue

                desired.setdefault(target_id.strip(), set()).add(normalized_ip)

    return {
        target_id: sorted(ips)
        for target_id, ips in sorted(desired.items())
    }


def _run_target_state(requester_email, target_id, ips, target, timeout_seconds, correlation_id):
    expected_count = len(ips)
    base = {
        "timestamp": _utc_now_iso(),
        "correlation_id": correlation_id,
        "target_id": target_id,
        "expected_count": expected_count,
        "requester_email": requester_email,
    }

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
        "--chain",
        REMOTE_SYNC_CHAIN,
        "--ips-json",
        json.dumps(ips),
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if completed.returncode == 0:
            result = {
                **base,
                "status": "success",
                "message": "remote update applied",
            }
        else:
            stderr = (completed.stderr or "").strip()[:300]
            result = {
                **base,
                "status": "failure",
                "message": stderr or f"remote command exited {completed.returncode}",
            }

    except subprocess.TimeoutExpired:
        result = {
            **base,
            "status": "failure",
            "message": "remote command timed out",
        }
    except Exception as exc:
        result = {
            **base,
            "status": "failure",
            "message": f"remote command error: {exc}",
        }

    _write_result_log(result)
    return result


def sync_targets(action, requester_email, ip, target_ids, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS):
    raise NotImplementedError("sync_targets has been replaced by sync_target_state/sync_all_target_states")


def sync_target_state(target_id, ips, requester_email, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS, correlation_id=None):
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id is required")

    normalized_ips = []
    for ip in ips:
        normalized_ips.append(str(ipaddress.ip_address(ip)))
    normalized_ips = sorted(set(normalized_ips))

    correlation_id = correlation_id or str(uuid.uuid4())

    targets = load_target_map()
    target = targets.get(target_id)
    if not target:
        result = {
            "timestamp": _utc_now_iso(),
            "correlation_id": correlation_id,
            "target_id": target_id,
            "expected_count": len(normalized_ips),
            "requester_email": requester_email,
            "status": "failure",
            "message": "target is not configured for remote sync",
        }
        _write_result_log(result)
        return result

    return _run_target_state(
        requester_email=requester_email,
        target_id=target_id,
        ips=normalized_ips,
        target=target,
        timeout_seconds=timeout_seconds,
        correlation_id=correlation_id,
    )


def sync_all_target_states(user_data, requester_email, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS, correlation_id=None):
    correlation_id = correlation_id or str(uuid.uuid4())
    targets = load_target_map()
    desired_state = compute_desired_target_state(user_data)
    results = []

    for target_id in sorted(targets):
        ips = desired_state.get(target_id, [])
        results.append(
            _run_target_state(
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
