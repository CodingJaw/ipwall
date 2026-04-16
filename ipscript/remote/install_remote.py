#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_GROUP = "ipwall"
DEFAULT_USER = "ipwall"
DEFAULT_INSTALL_DIR = "/opt/ipwall"
DEFAULT_CERT_DIR = "/etc/ipwall/certs"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Install IPWall remote shell wrapper over a root SSH session",
        epilog=(
            "Example:\n"
            "  python3 ipscript/remote/install_remote.py "
            "--host 203.0.113.10 --root-user root --user ipwall --group ipwall "
            "--install-dir /opt/ipwall --authorized-key-file /path/to/ipwall.pub "
            "--generate-certs --cert-cn ipwall.example.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Remote host/IP, user@host, or ssh://user@host[:port] install target",
    )
    parser.add_argument("--root-user", default="root", help="Remote SSH user with root privileges")
    parser.add_argument("--port", default=22, type=int, help="Remote SSH port")
    parser.add_argument("--ssh-key", help="SSH private key file")
    parser.add_argument("--group", default=DEFAULT_GROUP, help="Remote group name")
    parser.add_argument("--user", default=DEFAULT_USER, help="Remote user name")
    parser.add_argument("--install-dir", default=DEFAULT_INSTALL_DIR, help="Base install directory")
    parser.add_argument("--cert-dir", default=DEFAULT_CERT_DIR, help="Certificate directory for generated certs")
    parser.add_argument("--remote-script-name", default="remote_ipscript.py", help="Installed remote script name")
    parser.add_argument("--wrapper-name", default="ipwall-shell", help="Installed SSH shell-wrapper name")
    parser.add_argument("--sudoers-file", default="/etc/sudoers.d/ipwall-remote", help="Sudoers policy file path")
    parser.add_argument(
        "--authorized-key-file",
        help="Path to local SSH public key file to install with forced-command restrictions",
    )
    parser.add_argument(
        "--authorized-keys-path",
        default=".ssh/authorized_keys",
        help="Path inside the managed user's home for authorized keys",
    )
    parser.add_argument("--generate-certs", action="store_true", help="Generate and install self-signed cert/key")
    parser.add_argument("--cert-cn", default="ipwall.local", help="Certificate CN when --generate-certs is set")
    parser.add_argument("--cert-days", default=365, type=int, help="Certificate validity days")
    parser.add_argument("--dry-run", action="store_true", help="Print SSH/SCP calls without executing")
    return parser.parse_args()


def is_probably_public_key(text):
    if not text:
        return False
    line = text.strip().splitlines()[0].strip()
    if line.startswith("command="):
        return "ssh-" in line or "ecdsa-" in line or "sk-" in line
    return (
        line.startswith("ssh-")
        or line.startswith("ecdsa-")
        or line.startswith("sk-")
        or " ssh-" in line
        or " ecdsa-" in line
        or " sk-" in line
    )


def is_probably_private_key(text):
    if not text:
        return False
    return "BEGIN OPENSSH PRIVATE KEY" in text or "BEGIN RSA PRIVATE KEY" in text


def normalize_ssh_target(args):
    host_value = args.host.strip()
    if host_value.startswith("ssh://"):
        parsed = urlparse(host_value)
        if not parsed.hostname:
            raise ValueError(f"Invalid --host SSH URL: {host_value}")
        args.host = parsed.hostname
        if parsed.username:
            args.root_user = parsed.username
        if parsed.port:
            args.port = parsed.port
        return

    if "@" in host_value and "/" not in host_value:
        user_part, host_part = host_value.split("@", 1)
        if user_part:
            args.root_user = user_part
        if host_part:
            args.host = host_part


def validate_args(args):
    normalize_ssh_target(args)

    if args.ssh_key:
        ssh_key_path = Path(args.ssh_key)
        if not ssh_key_path.exists():
            raise ValueError(f"SSH identity file not found: {ssh_key_path}")
        key_text = ssh_key_path.read_text(encoding="utf-8", errors="ignore")
        if is_probably_public_key(key_text):
            if ssh_key_path.suffix == ".pub" and ssh_key_path.with_suffix("").exists():
                args.ssh_key = str(ssh_key_path.with_suffix(""))
            else:
                raise ValueError(
                    "SSH identity file appears to be a public key. --ssh-key must be a private key "
                    "(for example ~/.ssh/id_ed25519, not ~/.ssh/id_ed25519.pub)."
                )

    if args.authorized_key_file:
        auth_path = Path(args.authorized_key_file)
        if not auth_path.exists():
            raise ValueError(f"Authorized key file not found: {auth_path}")
        auth_text = auth_path.read_text(encoding="utf-8", errors="ignore").strip()
        if is_probably_private_key(auth_text):
            if auth_path.suffix == ".pub":
                raise ValueError(
                    "--authorized-key-file points to a private key. Provide a public key file instead."
                )
            pub_candidate = auth_path.with_suffix(".pub")
            if pub_candidate.exists():
                args.authorized_key_file = str(pub_candidate)
            else:
                raise ValueError(
                    "--authorized-key-file appears to be a private key. This argument must point to "
                    "a public key (.pub) or authorized_keys-formatted file."
                )
        elif not is_probably_public_key(auth_text):
            raise ValueError(
                "--authorized-key-file does not look like a valid SSH public key/authorized_keys entry."
            )


def quote(cmd_parts):
    return " ".join(shlex.quote(part) for part in cmd_parts)


def ssh_base(args):
    cmd = ["ssh", "-p", str(args.port)]
    if args.ssh_key:
        cmd.extend(["-i", args.ssh_key])
    cmd.append(f"{args.root_user}@{args.host}")
    return cmd


def scp_base(args):
    cmd = ["scp", "-P", str(args.port)]
    if args.ssh_key:
        cmd.extend(["-i", args.ssh_key])
    return cmd


def run_command(cmd, dry_run=False):
    print(f"$ {quote(cmd)}")
    if dry_run:
        return

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        if cmd and cmd[0] == "ssh" and exc.returncode == 255:
            print(
                "ERROR: SSH authentication/connection failed. Verify --host/--root-user/--port and "
                "pass a valid private key with --ssh-key if passwordless root access is required.",
                file=sys.stderr,
            )
        raise


def run_ssh(args, remote_script):
    cmd = ssh_base(args) + [remote_script]
    run_command(cmd, dry_run=args.dry_run)


def main():
    args = parse_args()
    try:
        validate_args(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    local_remote_script = Path(__file__).resolve().parent / "remote_ipscript.py"
    if not local_remote_script.exists():
        print(f"ERROR: missing local file: {local_remote_script}", file=sys.stderr)
        return 1

    remote_bin_dir = f"{args.install_dir.rstrip('/')}/bin"
    remote_script_path = f"{remote_bin_dir}/{args.remote_script_name}"
    remote_wrapper_path = f"{remote_bin_dir}/{args.wrapper_name}"
    group_q = shlex.quote(args.group)
    user_q = shlex.quote(args.user)
    install_dir_q = shlex.quote(args.install_dir)
    remote_bin_dir_q = shlex.quote(remote_bin_dir)
    remote_script_q = shlex.quote(remote_script_path)
    remote_wrapper_q = shlex.quote(remote_wrapper_path)
    home_dir_q = shlex.quote(f"/var/lib/{args.user}")
    user_home = f"/var/lib/{args.user}"

    # 1) Ensure group/user exist and are restricted.
    run_ssh(
        args,
        " ; ".join(
            [
                "set -e",
                f"if ! getent group {group_q} >/dev/null; then groupadd --system {group_q}; fi",
                (
                    f"if ! id -u {user_q} >/dev/null 2>&1; then "
                    f"useradd --system --gid {group_q} --create-home "
                    f"--home-dir {home_dir_q} --shell {remote_wrapper_q} {user_q}; "
                    "fi"
                ),
                f"mkdir -p {home_dir_q}",
                f"chown {user_q}:{group_q} {home_dir_q}",
                f"chmod 750 {home_dir_q}",
                f"mkdir -p {install_dir_q} {remote_bin_dir_q}",
                f"chown root:root {install_dir_q} {remote_bin_dir_q}",
                f"chmod 755 {install_dir_q} {remote_bin_dir_q}",
            ]
        ),
    )

    # 2) Copy remote app script as root-owned, not writable by ipwall user.
    tmp_remote_script = f"/tmp/{args.remote_script_name}.tmp"
    run_command(
        scp_base(args) + [str(local_remote_script), f"{args.root_user}@{args.host}:{tmp_remote_script}"],
        dry_run=args.dry_run,
    )
    run_ssh(
        args,
        " && ".join(
            [
                f"install -o root -g root -m 755 {shlex.quote(tmp_remote_script)} {remote_script_q}",
                f"rm -f {shlex.quote(tmp_remote_script)}",
            ]
        ),
    )

    # 3) Install shell wrapper that only executes the app via sudo.
    wrapper_content = (
        "#!/bin/sh\n"
        f"exec /usr/bin/sudo -n {remote_script_path} \"$@\"\n"
    )
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_wrapper:
        tmp_wrapper.write(wrapper_content)
        local_wrapper = tmp_wrapper.name

    try:
        tmp_remote_wrapper = f"/tmp/{args.wrapper_name}.tmp"
        run_command(
            scp_base(args) + [local_wrapper, f"{args.root_user}@{args.host}:{tmp_remote_wrapper}"],
            dry_run=args.dry_run,
        )
    finally:
        if os.path.exists(local_wrapper):
            os.unlink(local_wrapper)

    run_ssh(
        args,
        " && ".join(
            [
                f"install -o root -g root -m 755 {shlex.quote(tmp_remote_wrapper)} {remote_wrapper_q}",
                f"rm -f {shlex.quote(tmp_remote_wrapper)}",
                f"grep -qxF {remote_wrapper_q} /etc/shells || echo {remote_wrapper_q} >> /etc/shells",
                f"usermod --shell {remote_wrapper_q} {user_q}",
            ]
        ),
    )

    # 4) Allow only this app to run as root from the ipwall user.
    sudoers_content = (
        f"Defaults!{remote_script_path} !requiretty\n"
        f"{args.user} ALL=(root) NOPASSWD: {remote_script_path}\n"
    )
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_sudoers:
        tmp_sudoers.write(sudoers_content)
        local_sudoers = tmp_sudoers.name

    try:
        tmp_remote_sudoers = "/tmp/ipwall-remote.sudoers.tmp"
        run_command(
            scp_base(args) + [local_sudoers, f"{args.root_user}@{args.host}:{tmp_remote_sudoers}"],
            dry_run=args.dry_run,
        )
    finally:
        if os.path.exists(local_sudoers):
            os.unlink(local_sudoers)

    run_ssh(
        args,
        " && ".join(
            [
                f"install -o root -g root -m 440 {shlex.quote(tmp_remote_sudoers)} {shlex.quote(args.sudoers_file)}",
                f"rm -f {shlex.quote(tmp_remote_sudoers)}",
                f"visudo -cf {shlex.quote(args.sudoers_file)}",
            ]
        ),
    )

    # 4b) Optional authorized_keys install with strict forced-command restrictions.
    if args.authorized_key_file:
        key_path = Path(args.authorized_key_file)
        if not key_path.exists():
            print(f"ERROR: authorized key file not found: {key_path}", file=sys.stderr)
            return 1

        key_lines = [line.strip() for line in key_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not key_lines:
            print(f"ERROR: authorized key file is empty: {key_path}", file=sys.stderr)
            return 1

        forced_prefix = (
            f'command="{remote_wrapper_path}",'
            "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding "
        )
        restricted_lines = []
        for key_line in key_lines:
            if key_line.startswith("command="):
                restricted_lines.append(key_line)
            else:
                restricted_lines.append(f"{forced_prefix}{key_line}")

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_auth:
            tmp_auth.write("\n".join(restricted_lines) + "\n")
            local_auth = tmp_auth.name

        try:
            tmp_remote_auth = "/tmp/ipwall.authorized_keys.tmp"
            run_command(
                scp_base(args) + [local_auth, f"{args.root_user}@{args.host}:{tmp_remote_auth}"],
                dry_run=args.dry_run,
            )
        finally:
            if os.path.exists(local_auth):
                os.unlink(local_auth)

        remote_authorized_keys = f"{user_home.rstrip('/')}/{args.authorized_keys_path.lstrip('/')}"
        remote_authorized_keys_q = shlex.quote(remote_authorized_keys)
        remote_ssh_dir_q = shlex.quote(str(Path(remote_authorized_keys).parent))
        run_ssh(
            args,
            " && ".join(
                [
                    f"mkdir -p {remote_ssh_dir_q}",
                    f"chown {user_q}:{group_q} {remote_ssh_dir_q}",
                    f"chmod 700 {remote_ssh_dir_q}",
                    f"install -o {user_q} -g {group_q} -m 600 {shlex.quote(tmp_remote_auth)} {remote_authorized_keys_q}",
                    f"rm -f {shlex.quote(tmp_remote_auth)}",
                ]
            ),
        )

    # 5) Optional cert generation/application.
    if args.generate_certs:
        cert_path = f"{args.cert_dir.rstrip('/')}/ipwall.crt"
        key_path = f"{args.cert_dir.rstrip('/')}/ipwall.key"
        run_ssh(
            args,
            " && ".join(
                [
                    f"mkdir -p {shlex.quote(args.cert_dir)}",
                    (
                        "openssl req -x509 -nodes -newkey rsa:2048 "
                        f"-days {int(args.cert_days)} -subj {shlex.quote('/CN=' + args.cert_cn)} "
                        f"-keyout {shlex.quote(key_path)} -out {shlex.quote(cert_path)}"
                    ),
                    f"chown root:root {shlex.quote(cert_path)} {shlex.quote(key_path)}",
                    f"chmod 644 {shlex.quote(cert_path)}",
                    f"chmod 600 {shlex.quote(key_path)}",
                ]
            ),
        )

    print("Install completed.")
    print(f"Remote script: {remote_script_path}")
    print(f"SSH wrapper shell: {remote_wrapper_path}")
    print(f"Managed user/group: {args.user}:{args.group}")
    if args.authorized_key_file:
        print(f"Authorized keys: {user_home.rstrip('/')}/{args.authorized_keys_path.lstrip('/')}")
        print("Authorized key restrictions: forced command + no-pty/no-forwarding")
    else:
        print("Authorized keys: not installed (set --authorized-key-file to provision restricted SSH access)")
    if args.generate_certs:
        print(f"Certificates: {args.cert_dir.rstrip('/')}/ipwall.crt and ipwall.key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
