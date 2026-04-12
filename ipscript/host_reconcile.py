#!/usr/bin/env python3

import argparse
import ipaddress
import os
import sys
import uuid
from datetime import datetime, timezone

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_SRC_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "src"))
if REPO_SRC_DIR not in sys.path:
    sys.path.insert(0, REPO_SRC_DIR)

from remote_sync import (  # noqa: E402
    REMOTE_SYNC_TIMEOUT_SECONDS,
    compute_desired_target_state,
    load_target_map,
    sync_target_state,
)


def load_yaml(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_yaml(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False, default_flow_style=False)


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


def _normalize_ip(raw_ip):
    try:
        return str(ipaddress.ip_address(raw_ip))
    except Exception:
        return None


def prune_expired_ssh_targets(user_data):
    now = datetime.now(timezone.utc)
    changed = False

    if not isinstance(user_data, dict):
        return False

    for user in user_data.values():
        if not isinstance(user, dict):
            continue

        ip_entries = user.get("ips")
        if not isinstance(ip_entries, list):
            continue

        for entry in ip_entries:
            if not isinstance(entry, dict):
                continue

            current_targets = entry.get("ssh_targets")
            if not isinstance(current_targets, list):
                continue

            kept_targets = [
                target
                for target in current_targets
                if _target_state_active(target, now)
            ]

            if len(kept_targets) != len(current_targets):
                changed = True

            if kept_targets:
                entry["ssh_targets"] = kept_targets
            else:
                entry.pop("ssh_targets", None)

    return changed


def run_reconcile(user_data_path, requester_email, timeout_seconds):
    user_data = load_yaml(user_data_path)

    cleaned = prune_expired_ssh_targets(user_data)
    if cleaned:
        save_yaml(user_data_path, user_data)

    target_map = load_target_map()
    desired_state = compute_desired_target_state(user_data)
    correlation_id = str(uuid.uuid4())

    results = []
    for target_id in sorted(target_map):
        ips = desired_state.get(target_id, [])
        results.append(
            sync_target_state(
                target_id=target_id,
                ips=ips,
                requester_email=requester_email,
                timeout_seconds=timeout_seconds,
                correlation_id=correlation_id,
            )
        )

    succeeded = sum(1 for result in results if result.get("status") == "success")
    failed = len(results) - succeeded

    return {
        "correlation_id": correlation_id,
        "requested": len(results),
        "succeeded": succeeded,
        "failed": failed,
        "cleaned": cleaned,
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Reconcile full SSH state across local/remote targets")
    parser.add_argument("--user-data", default="user_data.yml")
    parser.add_argument("--requester-email", default="system:host-reconcile")
    parser.add_argument("--timeout-seconds", type=int, default=REMOTE_SYNC_TIMEOUT_SECONDS)

    args = parser.parse_args()

    result = run_reconcile(args.user_data, args.requester_email, args.timeout_seconds)

    print(
        "host_reconcile "
        f"correlation_id={result['correlation_id']} "
        f"requested={result['requested']} "
        f"succeeded={result['succeeded']} "
        f"failed={result['failed']} "
        f"cleaned={result['cleaned']}"
    )

    return 0 if result["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
