#!/usr/bin/env python3

import argparse
import fcntl
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

REMOTE_CHAIN = os.environ.get("IPWALL_REMOTE_CHAIN", "IPWALL_REMOTE_SSH")
SSH_PORT = os.environ.get("SSH_PORT", "22")
LOCK_FILE = os.environ.get("IPWALL_REMOTE_LOCK_FILE", "/var/run/ipwall.lock")
CHAIN_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,28}$")
RESERVED_CHAINS = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd, check=True, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(" ".join(cmd))
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    completed = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if check and completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(cmd)} :: {stderr}")
    return completed


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except Exception as exc:
        raise ValueError(f"invalid ip: {value}") from exc


def normalize_chain(value):
    if not isinstance(value, str):
        raise ValueError("chain name must be a string")

    chain = value.strip()
    if not chain:
        raise ValueError("chain name cannot be empty")

    if chain.upper() in RESERVED_CHAINS:
        raise ValueError(f"refusing to manage reserved chain: {chain}")

    if not CHAIN_NAME_PATTERN.fullmatch(chain):
        raise ValueError(f"invalid chain name: {chain}")

    return chain


def chain_exists(chain):
    completed = run_cmd(["iptables", "-L", chain], check=False)
    return completed.returncode == 0


def ensure_chain_and_jump(chain, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(f"iptables -N {chain}  # if missing")
            command_log.append(f"iptables -I INPUT -p tcp --dport {SSH_PORT} -j {chain}  # if missing")
        return

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


def ensure_return_rule(chain, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(f"iptables -A {chain} -j RETURN  # if missing")
        return

    check_return = run_cmd(["iptables", "-C", chain, "-j", "RETURN"], check=False, dry_run=dry_run)
    if check_return.returncode != 0:
        run_cmd(["iptables", "-A", chain, "-j", "RETURN"], dry_run=dry_run, command_log=command_log)


def ensure_established_rule(chain, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(
                f"iptables -I {chain} 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT  # if missing",
            )
        return

    check_established = run_cmd(
        [
            "iptables",
            "-C",
            chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        check=False,
    )
    if check_established.returncode != 0:
        run_cmd(
            [
                "iptables",
                "-I",
                chain,
                "1",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            dry_run=dry_run,
            command_log=command_log,
        )


def ensure_return_last(chain, dry_run=False, command_log=None):
    if dry_run:
        if isinstance(command_log, list):
            command_log.append(f"iptables -D {chain} -j RETURN  # until absent")
            command_log.append(f"iptables -A {chain} -j RETURN")
        return

    while True:
        delete_return = run_cmd(["iptables", "-D", chain, "-j", "RETURN"], check=False)
        if delete_return.returncode != 0:
            break
        if isinstance(command_log, list):
            command_log.append(f"iptables -D {chain} -j RETURN")

    run_cmd(["iptables", "-A", chain, "-j", "RETURN"], dry_run=dry_run, command_log=command_log)


def get_applied_ips(chain):
    completed = run_cmd(["iptables", "-S", chain], check=False)
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise RuntimeError(f"failed to inspect iptables chain {chain}: {stderr}")

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


def add_ip_rule(chain, ip_value, dry_run=False, command_log=None):
    run_cmd(
        [
            "iptables",
            "-I",
            chain,
            "2",
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


def reconcile_chain(chain, desired_ips, dry_run=False):
    command_log = []
    ensure_chain_and_jump(chain, dry_run=dry_run, command_log=command_log)
    ensure_established_rule(chain, dry_run=dry_run, command_log=command_log)
    ensure_return_last(chain, dry_run=dry_run, command_log=command_log)

    if dry_run:
        before = []
    else:
        before = get_applied_ips(chain)
    before_set = set(before)
    desired_set = set(desired_ips)

    to_remove = sorted(before_set - desired_set)
    to_add = sorted(desired_set - before_set)

    for ip_value in to_remove:
        remove_ip_rule(chain, ip_value, dry_run=dry_run, command_log=command_log)
    for ip_value in to_add:
        add_ip_rule(chain, ip_value, dry_run=dry_run, command_log=command_log)

    ensure_return_last(chain, dry_run=dry_run, command_log=command_log)

    return {
        "before": before,
        "desired": sorted(desired_set),
        "added": to_add,
        "removed": to_remove,
        "planned_commands": command_log,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="IPWall remote SSH chain wrapper (single-IP operations or JSON stdin sync)",
    )
    parser.add_argument("--chain", default=REMOTE_CHAIN, help="iptables chain name to manage")
    parser.add_argument("--dry-run", action="store_true", help="show planned iptables commands without applying")
    parser.add_argument("--add-ip", help="add a single IP to the managed chain")
    parser.add_argument("--del-ip", help="delete a single IP from the managed chain")
    return parser.parse_args()


def load_stdin_payload():
    raw = sys.stdin.read()
    if not raw.strip():
        raise RuntimeError("no JSON payload received on stdin")
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        raise RuntimeError("JSON payload must be an object")
    return loaded


def run_single_action(chain, dry_run, add_ip=None, del_ip=None):
    command_log = []
    ensure_chain_and_jump(chain, dry_run=dry_run, command_log=command_log)
    ensure_established_rule(chain, dry_run=dry_run, command_log=command_log)
    ensure_return_last(chain, dry_run=dry_run, command_log=command_log)

    action = None
    normalized = None
    if add_ip:
        action = "add_ip"
        normalized = normalize_ip(add_ip)
        add_ip_rule(chain, normalized, dry_run=dry_run, command_log=command_log)
    elif del_ip:
        action = "del_ip"
        normalized = normalize_ip(del_ip)
        remove_ip_rule(chain, normalized, dry_run=dry_run, command_log=command_log)

    ensure_return_last(chain, dry_run=dry_run, command_log=command_log)

    return {
        "ok": True,
        "mode": "single_action",
        "action": action,
        "chain": chain,
        "ip": normalized,
        "dry_run": bool(dry_run),
        "planned_commands": command_log,
        "at": utc_now_iso(),
    }


def run_payload_action(chain, dry_run, payload):
    payload_chain = payload.get("chain")
    if payload_chain is not None:
        requested_chain = normalize_chain(payload_chain)
        if requested_chain != chain:
            raise RuntimeError(
                f"payload chain override denied: requested={requested_chain} configured={chain}",
            )

    if isinstance(payload.get("dry_run"), bool):
        dry_run = payload["dry_run"]

    action = payload.get("action")
    if action in {"add_ip", "del_ip"}:
        ip_value = normalize_ip(payload.get("ip"))
        if action == "add_ip":
            result = run_single_action(chain, dry_run, add_ip=ip_value)
        else:
            result = run_single_action(chain, dry_run, del_ip=ip_value)
        result["mode"] = "json_action"
        result["request_id"] = payload.get("request_id")
        result["target_id"] = payload.get("target_id")
        return result

    raw_ips = payload.get("ips", [])
    if not isinstance(raw_ips, list):
        raise RuntimeError("payload field 'ips' must be a list")

    desired_ips = sorted({normalize_ip(ip_value) for ip_value in raw_ips})
    reconciled = reconcile_chain(chain, desired_ips, dry_run=dry_run)

    return {
        "ok": True,
        "mode": "json_sync",
        "chain": chain,
        "dry_run": bool(dry_run),
        "request_id": payload.get("request_id"),
        "target_id": payload.get("target_id"),
        **reconciled,
        "at": utc_now_iso(),
    }


def main():
    args = parse_args()
    if args.add_ip and args.del_ip:
        raise RuntimeError("use only one of --add-ip or --del-ip")

    chain = normalize_chain(args.chain)
    single_mode = bool(args.add_ip or args.del_ip)
    if (not args.dry_run) and os.geteuid() != 0:
        raise RuntimeError("must run as root unless using --dry-run")

    lock_path = LOCK_FILE
    if args.dry_run and os.geteuid() != 0:
        lock_path = "/tmp/ipwall.lock"
    with open(lock_path, "w", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle, fcntl.LOCK_EX)
        if single_mode:
            result = run_single_action(chain, args.dry_run, add_ip=args.add_ip, del_ip=args.del_ip)
        else:
            payload = load_stdin_payload()
            result = run_payload_action(chain, args.dry_run, payload)

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
