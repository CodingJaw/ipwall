#!/usr/bin/env python3

import ipaddress
import fcntl
import json
import os
import subprocess
import sys
import tempfile

SSH_PORT = "22"
LOCK_DIR = "/var/lock"


def eprint(message):
    print(message, file=sys.stderr)


def run_cmd(cmd):
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return completed.returncode == 0, (completed.stderr or "").strip()
    except Exception as exc:
        return False, str(exc)


def run_cmd_or_raise(cmd):
    ok, stderr = run_cmd(cmd)
    if not ok:
        raise RuntimeError(f"command failed: {' '.join(cmd)}: {stderr}")


def parse_request(stdin_text):
    try:
        payload = json.loads(stdin_text)
    except Exception as exc:
        return None, [f"invalid JSON payload: {exc}"]

    if not isinstance(payload, dict):
        return None, ["payload must be a JSON object"]

    errors = []

    chain = payload.get("chain")
    if not isinstance(chain, str) or not chain.strip():
        errors.append("chain must be a non-empty string")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not request_id.strip():
        errors.append("request_id must be a non-empty string")

    target_id = payload.get("target_id")
    if not isinstance(target_id, str) or not target_id.strip():
        errors.append("target_id must be a non-empty string")

    ips = payload.get("ips")
    if not isinstance(ips, list):
        errors.append("ips must be a JSON array")
        ips = []

    normalized_ips = []
    if isinstance(ips, list):
        for raw_ip in ips:
            if not isinstance(raw_ip, str):
                errors.append(f"ip must be a string: {raw_ip}")
                continue
            try:
                normalized_ips.append(str(ipaddress.ip_address(raw_ip)))
            except Exception:
                errors.append(f"invalid ip: {raw_ip}")

    normalized_ips = sorted(set(normalized_ips))

    return {
        "chain": chain.strip() if isinstance(chain, str) else "",
        "request_id": request_id.strip() if isinstance(request_id, str) else "",
        "target_id": target_id.strip() if isinstance(target_id, str) else "",
        "ips": normalized_ips,
    }, errors


def chain_exists(chain):
    exists, _ = run_cmd(["iptables", "-L", chain])
    return exists


def ensure_alias_chain(alias_chain):
    if not chain_exists(alias_chain):
        run_cmd_or_raise(["iptables", "-N", alias_chain])

    has_input_jump, _ = run_cmd([
        "iptables",
        "-C",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        SSH_PORT,
        "-j",
        alias_chain,
    ])
    if not has_input_jump:
        run_cmd_or_raise([
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            SSH_PORT,
            "-j",
            alias_chain,
        ])


def create_next_chain(next_chain, desired_ips):
    if chain_exists(next_chain):
        run_cmd_or_raise(["iptables", "-F", next_chain])
    else:
        run_cmd_or_raise(["iptables", "-N", next_chain])

    for ip in desired_ips:
        run_cmd_or_raise([
            "iptables",
            "-A",
            next_chain,
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
            "ACCEPT",
        ])

    run_cmd_or_raise(["iptables", "-A", next_chain, "-j", "RETURN"])


def point_alias_to_chain(alias_chain, target_chain):
    if not chain_exists(alias_chain):
        run_cmd_or_raise(["iptables", "-N", alias_chain])

    run_cmd_or_raise(["iptables", "-F", alias_chain])
    run_cmd_or_raise(["iptables", "-A", alias_chain, "-j", target_chain])


def cleanup_chain_if_unused(chain):
    if not chain_exists(chain):
        return

    in_use, _ = run_cmd(["iptables", "-C", "INPUT", "-j", chain])
    if in_use:
        return

    run_cmd_or_raise(["iptables", "-F", chain])
    run_cmd_or_raise(["iptables", "-X", chain])


def snapshot_rules():
    completed = subprocess.run(["iptables-save"], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"failed to snapshot rules: {(completed.stderr or '').strip()}")
    return completed.stdout


def restore_rules(snapshot):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as temp_file:
        temp_file.write(snapshot)
        temp_path = temp_file.name
    try:
        run_cmd_or_raise(["iptables-restore", temp_path])
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def acquire_lock(lock_name):
    os.makedirs(LOCK_DIR, exist_ok=True)
    lock_path = os.path.join(LOCK_DIR, f"{lock_name}.lock")
    lock_file = open(lock_path, "w", encoding="utf-8")
    fcntl.flock(lock_file, fcntl.LOCK_EX)
    return lock_file


def apply_desired_state(chain, desired_ips):
    alias_chain = chain
    next_chain = f"{chain}_NEXT"
    current_chain = f"{chain}_CURRENT"

    lock_file = acquire_lock(f"ipwall-sync-{chain}")
    snapshot = snapshot_rules()
    old_target_chain = None

    try:
        ensure_alias_chain(alias_chain)

        alias_rules = subprocess.run(
            ["iptables", "-S", alias_chain], capture_output=True, text=True, check=False
        )
        if alias_rules.returncode == 0:
            for line in (alias_rules.stdout or "").splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "-A" and parts[1] == alias_chain and "-j" in parts:
                    try:
                        old_target_chain = parts[parts.index("-j") + 1]
                        break
                    except Exception:
                        pass

        create_next_chain(next_chain, desired_ips)
        if chain_exists(current_chain):
            cleanup_chain_if_unused(current_chain)
        run_cmd_or_raise(["iptables", "-E", next_chain, current_chain])
        point_alias_to_chain(alias_chain, current_chain)

        if old_target_chain and old_target_chain not in (alias_chain, current_chain):
            cleanup_chain_if_unused(old_target_chain)

    except Exception:
        restore_rules(snapshot)
        raise
    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        finally:
            lock_file.close()


def get_chain_jump_target(chain):
    completed = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        return None

    for line in (completed.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "-A" or parts[1] != chain:
            continue
        if "-j" not in parts:
            continue
        try:
            return parts[parts.index("-j") + 1]
        except Exception:
            continue
    return None


def get_chain_applied_ips(chain, errors):
    try:
        completed = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True, check=False)
    except Exception as exc:
        errors.append(f"failed to read chain {chain}: {exc}")
        return []

    if completed.returncode != 0:
        errors.append(f"failed to read chain {chain}: {(completed.stderr or '').strip()}")
        return []

    applied = set()
    has_accept_rule = False
    for line in (completed.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0] != "-A" or parts[1] != chain:
            continue
        if "-j" not in parts:
            continue
        try:
            jump_target = parts[parts.index("-j") + 1]
        except Exception:
            continue
        if jump_target != "ACCEPT":
            continue
        has_accept_rule = True
        if "-s" not in parts:
            continue
        try:
            source = parts[parts.index("-s") + 1]
            applied.add(str(ipaddress.ip_network(source, strict=False).network_address))
        except Exception:
            errors.append(f"unable to parse source from rule: {line}")

    if has_accept_rule:
        return sorted(applied)

    target = get_chain_jump_target(chain)
    if target and target not in (chain, "RETURN", "ACCEPT", "DROP", "REJECT"):
        return get_chain_applied_ips(target, errors)

    return sorted(applied)


def emit_response(ok, applied_ips, missing, extra, errors):
    response = {
        "ok": bool(ok),
        "applied_ips": list(applied_ips),
        "missing": list(missing),
        "extra": list(extra),
        "errors": list(errors),
    }
    print(json.dumps(response, separators=(",", ":")))


def main():
    stdin_text = sys.stdin.read()
    payload, errors = parse_request(stdin_text)

    if payload is None:
        for err in errors:
            eprint(err)
        emit_response(False, [], [], [], errors)
        return 1

    desired_ips = payload["ips"]
    chain = payload["chain"]

    if errors:
        for err in errors:
            eprint(err)
        emit_response(False, [], desired_ips, [], errors)
        return 1

    try:
        apply_desired_state(chain, desired_ips)
    except Exception as exc:
        errors.append(str(exc))

    applied_ips = get_chain_applied_ips(chain, errors)
    missing = sorted(set(desired_ips) - set(applied_ips))
    extra = sorted(set(applied_ips) - set(desired_ips))

    ok = (len(errors) == 0) and (len(missing) == 0) and (len(extra) == 0)

    for err in errors:
        eprint(err)

    emit_response(ok, applied_ips, missing, extra, errors)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
