#!/usr/bin/env python3

import ipaddress
import json
import subprocess
import sys

SSH_PORT = "22"


def eprint(message):
    print(message, file=sys.stderr)


def run_cmd(cmd):
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return completed.returncode == 0, (completed.stderr or "").strip()
    except Exception as exc:
        return False, str(exc)


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


def ensure_chain(chain, errors):
    exists, _ = run_cmd(["iptables", "-L", chain])
    if not exists:
        created, stderr = run_cmd(["iptables", "-N", chain])
        if not created:
            errors.append(f"failed to create chain {chain}: {stderr}")
            return False

    has_jump, _ = run_cmd([
        "iptables",
        "-C",
        "INPUT",
        "-p",
        "tcp",
        "--dport",
        SSH_PORT,
        "-j",
        chain,
    ])
    if not has_jump:
        inserted, stderr = run_cmd([
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            SSH_PORT,
            "-j",
            chain,
        ])
        if not inserted:
            errors.append(f"failed to insert INPUT jump to {chain}: {stderr}")
            return False

    return True


def rebuild_chain(chain, desired_ips, errors):
    flushed, stderr = run_cmd(["iptables", "-F", chain])
    if not flushed:
        errors.append(f"failed to flush chain {chain}: {stderr}")
        return

    for ip in desired_ips:
        added, rule_stderr = run_cmd([
            "iptables",
            "-A",
            chain,
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
        if not added:
            errors.append(f"failed to add ACCEPT rule for {ip}: {rule_stderr}")

    appended, return_stderr = run_cmd(["iptables", "-A", chain, "-j", "RETURN"])
    if not appended:
        errors.append(f"failed to append RETURN to {chain}: {return_stderr}")


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
        if "-s" not in parts:
            continue
        try:
            source = parts[parts.index("-s") + 1]
            applied.add(str(ipaddress.ip_network(source, strict=False).network_address))
        except Exception:
            errors.append(f"unable to parse source from rule: {line}")

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

    if ensure_chain(chain, errors):
        rebuild_chain(chain, desired_ips, errors)

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
