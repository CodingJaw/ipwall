#!/usr/bin/env python3

import argparse
import ipaddress
import json
import random
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REMOTE_SCRIPT = SCRIPT_DIR / "remote_sync.py"


def random_test_ip():
    # 198.18.0.0/15 is benchmark space; avoid public ranges.
    octet_3 = random.randint(0, 255)
    octet_4 = random.randint(1, 254)
    return str(ipaddress.ip_address(f"198.18.{octet_3}.{octet_4}"))


def run_cmd(cmd):
    completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    return completed.returncode, stdout, stderr


def parse_json(stdout):
    try:
        return json.loads(stdout), None
    except Exception as exc:
        return None, f"invalid JSON output: {exc}"


def require_ok(step_name, code, payload, stderr):
    if code != 0:
        raise RuntimeError(f"{step_name} failed exit={code} stderr={stderr}")
    if not isinstance(payload, dict) or not payload.get("ok", False):
        raise RuntimeError(f"{step_name} did not report ok=true payload={payload}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local test harness for ipscript/client/remote_sync.py")
    parser.add_argument("--chain", default="IPWALL_SSH_TEST", help="isolated iptables chain used for testing")
    parser.add_argument("--ip", default="", help="explicit test IP (default random in 198.18.0.0/15)")
    args = parser.parse_args(argv)

    ip = args.ip or random_test_ip()
    print(f"[test] chain={args.chain} ip={ip}")

    dry_add_cmd = [str(REMOTE_SCRIPT), "--chain", args.chain, "--dry-run", "--add-ip", ip]
    code, stdout, stderr = run_cmd(dry_add_cmd)
    payload, parse_error = parse_json(stdout)
    if parse_error:
        raise RuntimeError(f"dry-run add parse error: {parse_error} stdout={stdout}")
    require_ok("dry-run add", code, payload, stderr)
    if ip in payload.get("applied_ips", []):
        raise RuntimeError("dry-run add unexpectedly changed applied_ips")

    add_cmd = [str(REMOTE_SCRIPT), "--chain", args.chain, "--add-ip", ip]
    code, stdout, stderr = run_cmd(add_cmd)
    payload, parse_error = parse_json(stdout)
    if parse_error:
        raise RuntimeError(f"add parse error: {parse_error} stdout={stdout}")
    require_ok("add", code, payload, stderr)
    if ip not in payload.get("applied_ips", []):
        raise RuntimeError(f"add did not apply test ip {ip}")

    dry_rm_cmd = [str(REMOTE_SCRIPT), "--chain", args.chain, "--dry-run", "--rm-ip", ip]
    code, stdout, stderr = run_cmd(dry_rm_cmd)
    payload, parse_error = parse_json(stdout)
    if parse_error:
        raise RuntimeError(f"dry-run remove parse error: {parse_error} stdout={stdout}")
    require_ok("dry-run remove", code, payload, stderr)
    if ip not in payload.get("applied_ips", []):
        raise RuntimeError("dry-run remove unexpectedly changed applied_ips")

    rm_cmd = [str(REMOTE_SCRIPT), "--chain", args.chain, "--rm-ip", ip]
    code, stdout, stderr = run_cmd(rm_cmd)
    payload, parse_error = parse_json(stdout)
    if parse_error:
        raise RuntimeError(f"remove parse error: {parse_error} stdout={stdout}")
    require_ok("remove", code, payload, stderr)
    if ip in payload.get("applied_ips", []):
        raise RuntimeError(f"remove did not clear test ip {ip}")

    print("[test] success")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[test] failure: {exc}", file=sys.stderr)
        raise SystemExit(1)
