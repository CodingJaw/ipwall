import ipaddress
import json
import os
import subprocess
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
        f"{result['timestamp']} action={result['action']} target_id={result['target_id']} "
        f"requester={result['requester_email']} ip={result['ip']} "
        f"status={result['status']} message={result['message']}"
    )

    try:
        with open(REMOTE_SYNC_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _run_target(action, requester_email, ip, target_id, target, timeout_seconds):
    base = {
        "timestamp": _utc_now_iso(),
        "action": action,
        "target_id": target_id,
        "requester_email": requester_email,
        "ip": ip,
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
        "--action",
        action,
        "--ip",
        ip,
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
    if action not in {"grant", "revoke"}:
        raise ValueError("action must be grant or revoke")

    ipaddress.ip_address(ip)

    targets = load_target_map()
    results = []

    for target_id in sorted(set(target_ids)):
        target = targets.get(target_id)
        if not target:
            result = {
                "timestamp": _utc_now_iso(),
                "action": action,
                "target_id": target_id,
                "requester_email": requester_email,
                "ip": ip,
                "status": "failure",
                "message": "target is not configured for remote sync",
            }
            _write_result_log(result)
            results.append(result)
            continue

        results.append(
            _run_target(
                action=action,
                requester_email=requester_email,
                ip=ip,
                target_id=target_id,
                target=target,
                timeout_seconds=timeout_seconds,
            )
        )

    successes = sum(1 for r in results if r["status"] == "success")

    return {
        "requested": len(set(target_ids)),
        "succeeded": successes,
        "failed": len(results) - successes,
        "results": results,
    }
