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


def _parse_sync_target(target):
    if not isinstance(target, dict):
        return None, "target must be an object"

    target_id = target.get("id")
    if not isinstance(target_id, str) or not target_id.strip():
        return None, "target id is required"

    if not bool(target.get("enabled", True)):
        return None, "target disabled"

    is_localhost = target.get("localhost") is True
    has_remote_fields = any(
        key in target for key in ("remote_host", "remote_user", "remote_port", "remote_script")
    )

    if is_localhost:
        if has_remote_fields:
            return None, "localhost target cannot define remote_* fields"
        return {
            "id": target_id.strip(),
            "type": "local",
            "script": REMOTE_SYNC_SCRIPT,
        }, None

    if "localhost" in target:
        return None, "localhost must be literal true when provided"

    host = target.get("remote_host")
    user = target.get("remote_user")
    if not all(isinstance(v, str) and v.strip() for v in (host, user)):
        return None, "remote target requires remote_host and remote_user"

    port = target.get("remote_port", 22)
    try:
        port = int(port)
    except Exception:
        return None, "remote_port must be an integer"

    if port < 1 or port > 65535:
        return None, "remote_port must be between 1 and 65535"

    return {
        "id": target_id.strip(),
        "type": "remote",
        "host": host.strip(),
        "user": user.strip(),
        "port": port,
        "script": str(target.get("remote_script", REMOTE_SYNC_SCRIPT)).strip() or REMOTE_SYNC_SCRIPT,
    }, None


def load_target_map(path=UI_CONFIG_FILE):
    target_map = {}
    raw = _load_config(path)
    allow_multiple_localhost_targets = bool(raw.get("allow_multiple_localhost_targets", False))
    localhost_seen = False

    for target in raw.get("ssh_targets", []):
        parsed_target, _ = _parse_sync_target(target)
        if not parsed_target:
            continue

        if parsed_target["type"] == "local":
            if localhost_seen and not allow_multiple_localhost_targets:
                continue
            localhost_seen = True

        target_map[parsed_target["id"]] = parsed_target

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

    # Canonical rule: only explicitly enabled targets are desired.
    # The GUI sets enabledssh=true at grant time for selected targets.
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
                # First-grant behavior:
                # GUI writes selected targets with enabledssh=true and a fresh
                # ssh_enabled_time immediately. That means the first admin grant
                # is desired right away and timer reconciliation will include it
                # on the next sync without waiting for any separate toggle step.
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


def _normalize_ip_list(values):
    normalized = []
    for value in values:
        normalized.append(str(ipaddress.ip_address(value)))
    return sorted(set(normalized))


def _validate_remote_response(stdout, expected_ips):
    if not isinstance(stdout, str) or not stdout.strip():
        return None, "remote stdout was empty"

    try:
        parsed = json.loads(stdout)
    except Exception as exc:
        return None, f"remote stdout was not valid JSON: {exc}"

    if not isinstance(parsed, dict):
        return None, "remote JSON response must be an object"

    required_types = {
        "ok": bool,
        "applied_ips": list,
        "missing": list,
        "extra": list,
        "errors": list,
    }
    for key, expected_type in required_types.items():
        if key not in parsed:
            return None, f"remote JSON response missing key '{key}'"
        if not isinstance(parsed[key], expected_type):
            return None, f"remote JSON response key '{key}' must be {expected_type.__name__}"

    try:
        applied_ips = _normalize_ip_list(parsed.get("applied_ips", []))
    except Exception as exc:
        return None, f"remote applied_ips contained invalid IPs: {exc}"

    if applied_ips != expected_ips:
        return parsed, (
            "remote applied_ips mismatch "
            f"expected={expected_ips} got={applied_ips}"
        )

    return parsed, None


def _run_local_target_state(requester_email, target_id, ips, target, timeout_seconds, correlation_id):
    expected_count = len(ips)
    request_id = str(uuid.uuid4())
    base = {
        "timestamp": _utc_now_iso(),
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

    cmd = [target["script"]]

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
        response, response_error = _validate_remote_response(completed.stdout, ips)
        local_ok = bool(response and response.get("ok"))

        if completed.returncode == 0 and local_ok and response_error is None:
            result = {
                **base,
                "status": "success",
                "message": "localhost update applied and verified",
            }
        else:
            error_parts = []
            if completed.returncode != 0:
                error_parts.append(f"localhost command exited {completed.returncode}")
            if response_error:
                error_parts.append(response_error)
            if response and not local_ok:
                errors = response.get("errors", [])
                if errors:
                    error_parts.append(f"localhost errors={errors}")
            if stderr:
                error_parts.append(f"stderr={stderr[:300]}")

            result = {
                **base,
                "status": "failure",
                "message": "; ".join(error_parts)[:700] or "localhost command failed",
            }

    except subprocess.TimeoutExpired:
        result = {
            **base,
            "status": "failure",
            "message": "localhost command timed out",
        }
    except Exception as exc:
        result = {
            **base,
            "status": "failure",
            "message": f"localhost command error: {exc}",
        }

    _write_result_log(result)
    return result


def _run_remote_target_state(requester_email, target_id, ips, target, timeout_seconds, correlation_id):
    expected_count = len(ips)
    request_id = str(uuid.uuid4())
    base = {
        "timestamp": _utc_now_iso(),
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
        response, response_error = _validate_remote_response(completed.stdout, ips)
        remote_ok = bool(response and response.get("ok"))

        if completed.returncode == 0 and remote_ok and response_error is None:
            result = {
                **base,
                "status": "success",
                "message": "remote update applied and verified",
            }
        else:
            error_parts = []
            if completed.returncode != 0:
                error_parts.append(f"remote command exited {completed.returncode}")
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
                "message": "; ".join(error_parts)[:700] or "remote command failed",
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


def _run_target_state(requester_email, target_id, ips, target, timeout_seconds, correlation_id):
    if target.get("type") == "local":
        return _run_local_target_state(
            requester_email=requester_email,
            target_id=target_id,
            ips=ips,
            target=target,
            timeout_seconds=timeout_seconds,
            correlation_id=correlation_id,
        )

    return _run_remote_target_state(
        requester_email=requester_email,
        target_id=target_id,
        ips=ips,
        target=target,
        timeout_seconds=timeout_seconds,
        correlation_id=correlation_id,
    )


def sync_targets(action, requester_email, ip, target_ids, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS):
    raise NotImplementedError("sync_targets has been replaced by sync_target_state/sync_all_target_states")


def sync_target_state(target_id, ips, requester_email, timeout_seconds=REMOTE_SYNC_TIMEOUT_SECONDS, correlation_id=None):
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id is required")

    normalized_ips = _normalize_ip_list(ips)

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
