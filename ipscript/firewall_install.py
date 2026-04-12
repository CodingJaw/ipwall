#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys

DEFAULT_HOST_INSTALL_DIR = "/opt/ipwall"
HOST_SCRIPT_NAME = "remote_sync.py"
DEFAULT_HOST_SOURCE = "./remote_sync.py"

DEFAULT_REMOTE_INSTALL_PATH = "/usr/local/bin/ipwall-firewall-sync"
DEFAULT_REMOTE_SOURCE = "./firewall_sync.py"

DEFAULT_TIMER = 60
DEFAULT_USERDATA = "/docker/ipwall/user_data.yml"

SYSTEMD_SERVICE = "ipwall-firewall-sync.service"
SYSTEMD_TIMER = "ipwall-firewall-sync.timer"

AUDIT_LOG = "/var/log/ipwall_ssh_audit.log"
FIREWALL_CHAIN = "IPWALL_SSH"


# --------------------------------------------------
# Utility
# --------------------------------------------------


def run(cmd, dry=False):
    if dry:
        print("[dry-run]", " ".join(cmd))
        return
    subprocess.run(cmd, check=False)


def require_root():
    if os.geteuid() != 0:
        print("ERROR: Must run as root.")
        sys.exit(1)


def command_exists(cmd):
    return shutil.which(cmd) is not None


# --------------------------------------------------
# Examples
# --------------------------------------------------


def show_examples():
    print(
        f"""
IPWall Firewall Installer Examples
==================================

Host mode install (script + systemd service/timer)
---------------------------------------------------
sudo python3 firewall_install.py --install --mode host

Host mode with custom timer (120 seconds)
------------------------------------------
sudo python3 firewall_install.py --install --mode host --timer 120

Host mode with custom script source/user_data.yml
--------------------------------------------------
sudo python3 firewall_install.py --install --mode host \\
    --host-source /srv/ipwall/remote_sync.py \\
    --userdata /srv/ipwall/user_data.yml

Remote mode install (script only, no timer)
--------------------------------------------
sudo python3 firewall_install.py --install --mode remote

Remote mode install from explicit source/path
---------------------------------------------
sudo python3 firewall_install.py --install --mode remote \\
    --remote-source /srv/ipwall/firewall_sync.py \\
    --remote-path {DEFAULT_REMOTE_INSTALL_PATH}

Upgrade host reconciler script
------------------------------
sudo python3 firewall_install.py --upgrade --mode host

Upgrade remote applier script
-----------------------------
sudo python3 firewall_install.py --upgrade --mode remote

Enable host systemd timer
-------------------------
sudo python3 firewall_install.py --enable

Disable host systemd timer
--------------------------
sudo python3 firewall_install.py --disable

Check host status
-----------------
sudo python3 firewall_install.py --status

Run host diagnostics
--------------------
sudo python3 firewall_install.py --doctor

Remove host installation (timer + script)
-----------------------------------------
sudo python3 firewall_install.py --remove --mode host

Remove remote installation (script only)
----------------------------------------
sudo python3 firewall_install.py --remove --mode remote

SSH target config path must match remote installed path exactly
---------------------------------------------------------------
"remote_script": "{DEFAULT_REMOTE_INSTALL_PATH}"
"""
    )


# --------------------------------------------------
# Script install / upgrade
# --------------------------------------------------


def update_userdata(script_path, userdata):
    with open(script_path, encoding="utf-8") as f:
        content = f.read()

    new_lines = []
    for line in content.splitlines():
        if line.startswith("USER_DATA_FILE"):
            line = f'USER_DATA_FILE = "{userdata}"'
        new_lines.append(line)

    with open(script_path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines) + "\n")


def install_file(source, dest, dry):
    dest_dir = os.path.dirname(dest)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    if dry:
        print(f"[dry-run] install script {source} -> {dest}")
        return

    shutil.copy2(source, dest)
    os.chmod(dest, 0o755)


def install_host_script(source, installdir, userdata, dry):
    dest = os.path.join(installdir, HOST_SCRIPT_NAME)
    install_file(source, dest, dry)

    if userdata and not dry:
        update_userdata(dest, userdata)

    print(f"Installed host script -> {dest}")
    return dest


def install_remote_script(source, remote_path, dry):
    install_file(source, remote_path, dry)
    print(f"Installed remote script -> {remote_path}")
    return remote_path


def upgrade_host_script(source, installdir, userdata, dry):
    dest = os.path.join(installdir, HOST_SCRIPT_NAME)

    if not os.path.exists(dest):
        print("No installed host script found. Use --install --mode host first.")
        return

    if dry:
        print(f"[dry-run] upgrade {dest}")
        return

    shutil.copy2(source, dest)
    os.chmod(dest, 0o755)

    if userdata:
        update_userdata(dest, userdata)

    print("Host script upgraded.")


def upgrade_remote_script(source, remote_path, dry):
    if not os.path.exists(remote_path):
        print("No installed remote script found. Use --install --mode remote first.")
        return

    if dry:
        print(f"[dry-run] upgrade {remote_path}")
        return

    shutil.copy2(source, remote_path)
    os.chmod(remote_path, 0o755)

    print("Remote script upgraded.")


# --------------------------------------------------
# Systemd install
# --------------------------------------------------


def install_systemd(script_path, timer, dry):
    service_file = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    timer_file = f"/etc/systemd/system/{SYSTEMD_TIMER}"

    service = f"""
[Unit]
Description=IPWall Firewall Sync

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path}
"""

    timer_conf = f"""
[Unit]
Description=Run IPWall firewall sync

[Timer]
OnBootSec=30
OnUnitActiveSec={timer}

[Install]
WantedBy=timers.target
"""

    if dry:
        print("[dry-run] write", service_file)
        print("[dry-run] write", timer_file)
        return

    with open(service_file, "w", encoding="utf-8") as f:
        f.write(service.strip() + "\n")

    with open(timer_file, "w", encoding="utf-8") as f:
        f.write(timer_conf.strip() + "\n")

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", SYSTEMD_TIMER])
    run(["systemctl", "start", SYSTEMD_TIMER])

    print("Host systemd timer installed and started.")


# --------------------------------------------------
# Enable / Disable
# --------------------------------------------------


def enable_systemd():
    run(["systemctl", "enable", SYSTEMD_TIMER])
    run(["systemctl", "start", SYSTEMD_TIMER])

    print("Timer enabled and started.")


def disable_systemd():
    run(["systemctl", "stop", SYSTEMD_TIMER])
    run(["systemctl", "disable", SYSTEMD_TIMER])

    print("Timer disabled.")


# --------------------------------------------------
# Remove installation
# --------------------------------------------------


def remove_host(installdir, dry):
    service = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    timer = f"/etc/systemd/system/{SYSTEMD_TIMER}"
    script = os.path.join(installdir, HOST_SCRIPT_NAME)

    if dry:
        print("[dry-run] remove", service)
        print("[dry-run] remove", timer)
        print("[dry-run] remove", script)
        return

    run(["systemctl", "stop", SYSTEMD_TIMER])
    run(["systemctl", "disable", SYSTEMD_TIMER])

    if os.path.exists(service):
        os.remove(service)

    if os.path.exists(timer):
        os.remove(timer)

    if os.path.exists(script):
        os.remove(script)

    run(["systemctl", "daemon-reload"])

    print("Removed host installation.")


def remove_remote(remote_path, dry):
    if dry:
        print("[dry-run] remove", remote_path)
        return

    if os.path.exists(remote_path):
        os.remove(remote_path)

    print("Removed remote installation.")


# --------------------------------------------------
# Status
# --------------------------------------------------


def show_status():
    print("\nIPWall Firewall Sync Status (host mode)\n")

    subprocess.run(["systemctl", "status", SYSTEMD_TIMER])
    subprocess.run(["systemctl", "status", SYSTEMD_SERVICE])


# --------------------------------------------------
# Doctor diagnostics
# --------------------------------------------------


def doctor(installdir, remote_path):
    print("\nIPWall Doctor Diagnostics\n")

    checks = []

    checks.append(("python3 installed", command_exists("python3")))
    checks.append(("iptables installed", command_exists("iptables")))

    host_script = os.path.join(installdir, HOST_SCRIPT_NAME)
    checks.append(("host remote_sync installed", os.path.exists(host_script)))
    checks.append(("remote applier installed", os.path.exists(remote_path)))

    checks.append(("user_data readable", os.path.exists(DEFAULT_USERDATA)))

    service_file = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    checks.append(("systemd service installed", os.path.exists(service_file)))

    try:
        subprocess.check_output(["systemctl", "is-active", SYSTEMD_TIMER])
        active = True
    except Exception:
        active = False

    checks.append(("systemd timer active", active))

    try:
        subprocess.check_output(["iptables", "-L", FIREWALL_CHAIN])
        chain = True
    except Exception:
        chain = False

    checks.append(("firewall chain exists", chain))

    try:
        open(AUDIT_LOG, "a", encoding="utf-8").close()
        log_ok = True
    except Exception:
        log_ok = False

    checks.append(("audit log writable", log_ok))

    for name, ok in checks:
        status = "OK" if ok else "FAIL"
        print(f"{name:30} {status}")

    print()


# --------------------------------------------------
# Main
# --------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="IPWall firewall installer")

    parser.add_argument("--install", action="store_true")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--upgrade", action="store_true")

    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")

    parser.add_argument("--status", action="store_true")
    parser.add_argument("--examples", action="store_true")
    parser.add_argument("--doctor", action="store_true")

    parser.add_argument("--mode", choices=["host", "remote"], default="host")
    parser.add_argument("--timer", type=int, default=DEFAULT_TIMER)

    parser.add_argument("--installdir", default=DEFAULT_HOST_INSTALL_DIR)
    parser.add_argument("--userdata", default=None)

    parser.add_argument("--host-source", default=DEFAULT_HOST_SOURCE)
    parser.add_argument("--remote-source", default=DEFAULT_REMOTE_SOURCE)
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_INSTALL_PATH)

    # Backward-compatible alias. --host-source / --remote-source are preferred.
    parser.add_argument("--source", default=None)

    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.examples:
        show_examples()
        return

    require_root()

    if args.doctor:
        doctor(args.installdir, args.remote_path)
        return

    if args.status:
        show_status()
        return

    if args.enable:
        enable_systemd()
        return

    if args.disable:
        disable_systemd()
        return

    if args.install:
        if args.mode == "host":
            host_source = args.source or args.host_source
            script = install_host_script(host_source, args.installdir, args.userdata, args.dry_run)
            install_systemd(script, args.timer, args.dry_run)
            print("Host mode installation complete.")
            return

        remote_source = args.source or args.remote_source
        install_remote_script(remote_source, args.remote_path, args.dry_run)
        print("Remote mode installation complete (no timer installed).")
        return

    if args.upgrade:
        if args.mode == "host":
            host_source = args.source or args.host_source
            upgrade_host_script(host_source, args.installdir, args.userdata, args.dry_run)
            return

        remote_source = args.source or args.remote_source
        upgrade_remote_script(remote_source, args.remote_path, args.dry_run)
        return

    if args.remove:
        if args.mode == "host":
            remove_host(args.installdir, args.dry_run)
            return

        remove_remote(args.remote_path, args.dry_run)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
