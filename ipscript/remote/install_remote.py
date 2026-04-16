#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
import re
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
        "--generated-authorized-key-prefix",
        help=(
            "When --authorized-key-file is omitted, generate an SSH keypair for the managed user "
            "using this output path prefix (default: ./ipwall_<host>_<user>)"
        ),
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
            if ssh_key_path.suffix == ".pub" and Path(str(ssh_key_path)[:-4]).exists():
                args.ssh_key = str(Path(str(ssh_key_path)[:-4]))
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
            pub_candidate = Path(f"{auth_path}.pub")
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


def build_restricted_authorized_keys(args, remote_wrapper_path):
    forced_prefix = (
        f'command="{remote_wrapper_path}",'
        "no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding "
    )

    generated_private_key = None
    if args.authorized_key_file:
        source_key_path = Path(args.authorized_key_file)
        key_lines = [line.strip() for line in source_key_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not key_lines:
            raise ValueError(f"authorized key file is empty: {source_key_path}")
    else:
        safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "_", args.host)
        key_prefix = (
            Path(args.generated_authorized_key_prefix)
            if args.generated_authorized_key_prefix
            else Path.cwd() / f"ipwall_{safe_host}_{args.user}"
        )
        if args.dry_run:
            key_lines = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDRYRUNVVEVfRFJZX1JVTl9QTEFDRUhPTERFUg== ipwall-dry-run"]
            print(
                "INFO: --authorized-key-file not provided; dry-run mode is using a placeholder generated key.",
                file=sys.stderr,
            )
        else:
            key_prefix.parent.mkdir(parents=True, exist_ok=True)
            key_prefix_pub = Path(f"{key_prefix}.pub")
            if key_prefix_pub.exists():
                pub_text = key_prefix_pub.read_text(encoding="utf-8").strip()
                generated_private_key = str(key_prefix) if key_prefix.exists() else None
                print(f"INFO: Reusing existing generated public key: {key_prefix_pub}", file=sys.stderr)
                if not pub_text:
                    raise ValueError(f"Existing generated public key is empty: {key_prefix_pub}")
            elif key_prefix.exists():
                try:
                    pub_text = subprocess.check_output(
                        ["ssh-keygen", "-y", "-f", str(key_prefix)],
                        text=True,
                    ).strip()
                except subprocess.CalledProcessError as exc:
                    raise ValueError(
                        f"Failed to derive public key from existing private key: {key_prefix} ({exc})"
                    ) from exc
                key_prefix_pub.write_text(pub_text + "\n", encoding="utf-8")
                generated_private_key = str(key_prefix)
                print(f"INFO: Rebuilt missing generated public key: {key_prefix_pub}", file=sys.stderr)
            else:
                run_command(
                    ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_prefix)],
                    dry_run=False,
                )
                generated_private_key = str(key_prefix)
                pub_text = key_prefix_pub.read_text(encoding="utf-8").strip()
                print(f"INFO: Generated new managed-user keypair: {key_prefix}", file=sys.stderr)
            key_lines = [pub_text] if pub_text else []
            if not key_lines:
                raise ValueError(f"Generated key is empty: {key_prefix}.pub")

    restricted_lines = []
    for key_line in key_lines:
        if key_line.startswith("command="):
            restricted_lines.append(key_line)
        else:
            restricted_lines.append(f"{forced_prefix}{key_line}")

    return restricted_lines, generated_private_key


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
                    f"--home-dir {home_dir_q} --shell /usr/sbin/nologin {user_q}; "
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

    # 4b) Install authorized_keys with strict forced-command restrictions.
    try:
        restricted_lines, generated_private_key = build_restricted_authorized_keys(args, remote_wrapper_path)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

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
    print(f"Authorized keys: {user_home.rstrip('/')}/{args.authorized_keys_path.lstrip('/')}")
    print("Authorized key restrictions: forced command + no-pty/no-forwarding")
    if not args.authorized_key_file:
        if args.dry_run:
            print("Generated user SSH keypair: dry-run placeholder only (no local files created)")
        elif generated_private_key:
            print(f"Generated user SSH keypair (private key path): {generated_private_key}")
        else:
            print("Generated user SSH keypair: reused existing public key only (private key path unavailable)")
    if args.generate_certs:
        print(f"Certificates: {args.cert_dir.rstrip('/')}/ipwall.crt and ipwall.key")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
