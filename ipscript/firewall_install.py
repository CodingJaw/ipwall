#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys

DEFAULT_INSTALL_DIR = "/opt/ipwall"
DEFAULT_SCRIPT_NAME = "host_reconcile.py"
DEFAULT_REMOTE_SYNC_NAME = "remote_sync.py"
DEFAULT_TIMER = 60
DEFAULT_USERDATA = "/docker/ipwall/user_data.yml"

SYSTEMD_SERVICE = "ipwall-host-reconcile.service"
SYSTEMD_TIMER = "ipwall-host-reconcile.timer"

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

    print("""
IPWall Host Reconcile Installer Examples
==================================

Install using systemd (recommended)
-----------------------------------
sudo python3 firewall_install.py --install

Install with custom timer (120 seconds)
---------------------------------------
sudo python3 firewall_install.py --install --timer 120

Install to custom directory
---------------------------
sudo python3 firewall_install.py --install --installdir /usr/local/ipwall

Override user_data.yml location
-------------------------------
sudo python3 firewall_install.py --install \\
    --userdata /srv/ipwall/user_data.yml

Install using cron instead of systemd
-------------------------------------
sudo python3 firewall_install.py --install --method cron

Upgrade host_reconcile.py
------------------------
sudo python3 firewall_install.py --upgrade

Enable systemd timer
--------------------
sudo python3 firewall_install.py --enable

Disable systemd timer
---------------------
sudo python3 firewall_install.py --disable

Check status
------------
sudo python3 firewall_install.py --status

Run installation diagnostics
----------------------------
sudo python3 firewall_install.py --doctor

Remove everything
-----------------
sudo python3 firewall_install.py --remove
""")


# --------------------------------------------------
# Script install / upgrade
# --------------------------------------------------

def update_userdata(script_path, userdata):

    with open(script_path) as f:
        content = f.read()

    new_lines = []

    for line in content.splitlines():

        if line.startswith("USER_DATA_FILE"):
            line = f'USER_DATA_FILE = "{userdata}"'

        new_lines.append(line)

    with open(script_path, "w") as f:
        f.write("\n".join(new_lines) + "\n")


def install_script(source, remote_sync_source, installdir, userdata, dry):

    os.makedirs(installdir, exist_ok=True)

    dest = os.path.join(installdir, DEFAULT_SCRIPT_NAME)

    remote_sync_dest = os.path.join(installdir, DEFAULT_REMOTE_SYNC_NAME)

    if dry:
        print(f"[dry-run] install script {source} -> {dest}")
        print(f"[dry-run] install dependency {remote_sync_source} -> {remote_sync_dest}")
        return dest

    shutil.copy2(source, dest)
    shutil.copy2(remote_sync_source, remote_sync_dest)
    os.chmod(dest, 0o755)
    os.chmod(remote_sync_dest, 0o644)

    if userdata:
        update_userdata(dest, userdata)

    print(f"Installed script -> {dest}")

    return dest


def upgrade_script(source, remote_sync_source, installdir, userdata, dry):

    dest = os.path.join(installdir, DEFAULT_SCRIPT_NAME)

    if not os.path.exists(dest):
        print("No installed script found. Use --install first.")
        return

    if dry:
        print(f"[dry-run] upgrade {dest}")
        print(f"[dry-run] upgrade {os.path.join(installdir, DEFAULT_REMOTE_SYNC_NAME)}")
        return

    shutil.copy2(source, dest)
    shutil.copy2(remote_sync_source, os.path.join(installdir, DEFAULT_REMOTE_SYNC_NAME))

    if userdata:
        update_userdata(dest, userdata)

    print("Script upgraded.")


# --------------------------------------------------
# Systemd install
# --------------------------------------------------

def install_systemd(script_path, timer, userdata, dry):

    service_file = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    timer_file = f"/etc/systemd/system/{SYSTEMD_TIMER}"

    userdata_arg = f" --user-data {userdata}" if userdata else ""

    service = f"""
[Unit]
Description=IPWall Host Reconcile Sync

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script_path}{userdata_arg}
"""

    timer_conf = f"""
[Unit]
Description=Run IPWall host reconcile sync

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

    with open(service_file, "w") as f:
        f.write(service.strip() + "\n")

    with open(timer_file, "w") as f:
        f.write(timer_conf.strip() + "\n")

    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", SYSTEMD_TIMER])
    run(["systemctl", "start", SYSTEMD_TIMER])

    print("Systemd timer installed and started.")


# --------------------------------------------------
# Cron install
# --------------------------------------------------

def install_cron(script_path, timer, userdata, dry):

    minutes = max(1, timer // 60)

    userdata_arg = f" --user-data {userdata}" if userdata else ""
    cron_line = f"*/{minutes} * * * * /usr/bin/python3 {script_path}{userdata_arg}"

    if dry:
        print("[dry-run] cron:", cron_line)
        return

    try:
        existing = subprocess.check_output(["crontab", "-l"], text=True)
    except subprocess.CalledProcessError:
        existing = ""

    lines = [
        l for l in existing.splitlines()
        if DEFAULT_SCRIPT_NAME not in l and "firewall_sync.py" not in l
    ]
    lines.append(cron_line)

    p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
    p.communicate("\n".join(lines) + "\n")

    print("Cron job installed.")


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

def remove_all(installdir, dry):

    service = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    timer = f"/etc/systemd/system/{SYSTEMD_TIMER}"
    script = os.path.join(installdir, DEFAULT_SCRIPT_NAME)
    remote_sync = os.path.join(installdir, DEFAULT_REMOTE_SYNC_NAME)

    if dry:
        print("[dry-run] remove", service)
        print("[dry-run] remove", timer)
        print("[dry-run] remove", script)
        print("[dry-run] remove", remote_sync)
        return

    run(["systemctl", "stop", SYSTEMD_TIMER])
    run(["systemctl", "disable", SYSTEMD_TIMER])

    if os.path.exists(service):
        os.remove(service)

    if os.path.exists(timer):
        os.remove(timer)

    if os.path.exists(script):
        os.remove(script)
    if os.path.exists(remote_sync):
        os.remove(remote_sync)

    run(["systemctl", "daemon-reload"])

    try:
        existing = subprocess.check_output(["crontab", "-l"], text=True)
        lines = [
            l for l in existing.splitlines()
            if DEFAULT_SCRIPT_NAME not in l and "firewall_sync.py" not in l
        ]

        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        p.communicate("\n".join(lines) + "\n")
    except:
        pass

    print("Removed installation.")


# --------------------------------------------------
# Status
# --------------------------------------------------

def show_status():

    print("\nIPWall Host Reconcile Status\n")

    subprocess.run(["systemctl", "status", SYSTEMD_TIMER])
    subprocess.run(["systemctl", "status", SYSTEMD_SERVICE])

    print("\nCron entries:\n")

    try:
        cron = subprocess.check_output(["crontab", "-l"], text=True)
        print(cron)
    except subprocess.CalledProcessError:
        print("No cron entries.")


# --------------------------------------------------
# Doctor diagnostics
# --------------------------------------------------

def doctor():

    print("\nIPWall Doctor Diagnostics\n")

    checks = []

    checks.append(("python3 installed", command_exists("python3")))
    checks.append(("iptables installed", command_exists("iptables")))

    script = os.path.join(DEFAULT_INSTALL_DIR, DEFAULT_SCRIPT_NAME)
    checks.append(("host_reconcile installed", os.path.exists(script)))
    checks.append((
        "remote_sync dependency installed",
        os.path.exists(os.path.join(DEFAULT_INSTALL_DIR, DEFAULT_REMOTE_SYNC_NAME))
    ))

    checks.append(("user_data readable", os.path.exists(DEFAULT_USERDATA)))

    service_file = f"/etc/systemd/system/{SYSTEMD_SERVICE}"
    checks.append(("systemd service installed", os.path.exists(service_file)))

    try:
        subprocess.check_output(["systemctl", "is-active", SYSTEMD_TIMER])
        active = True
    except:
        active = False

    checks.append(("systemd timer active", active))

    try:
        subprocess.check_output(["iptables", "-L", FIREWALL_CHAIN])
        chain = True
    except:
        chain = False

    checks.append(("firewall chain exists", chain))

    for name, ok in checks:

        status = "OK" if ok else "FAIL"

        print(f"{name:30} {status}")

    print()


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(description="IPWall host reconcile installer")

    parser.add_argument("--install", action="store_true")
    parser.add_argument("--remove", action="store_true")
    parser.add_argument("--upgrade", action="store_true")

    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")

    parser.add_argument("--status", action="store_true")
    parser.add_argument("--examples", action="store_true")
    parser.add_argument("--doctor", action="store_true")

    parser.add_argument("--method", choices=["systemd", "cron"], default="systemd")
    parser.add_argument("--timer", type=int, default=DEFAULT_TIMER)

    parser.add_argument("--installdir", default=DEFAULT_INSTALL_DIR)
    parser.add_argument("--userdata", default=None)

    parser.add_argument("--source", default="./host_reconcile.py")
    parser.add_argument("--remote-sync-source", default="../src/remote_sync.py")

    parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if args.examples:
        show_examples()
        return

    require_root()

    if args.doctor:
        doctor()
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

        script = install_script(
            args.source,
            args.remote_sync_source,
            args.installdir,
            args.userdata,
            args.dry_run
        )

        if args.method == "systemd":
            install_systemd(script, args.timer, args.userdata, args.dry_run)

        elif args.method == "cron":
            install_cron(script, args.timer, args.userdata, args.dry_run)

        print("Installation complete.")
        return

    if args.upgrade:
        upgrade_script(
            args.source,
            args.remote_sync_source,
            args.installdir,
            args.userdata,
            args.dry_run
        )
        return

    if args.remove:
        remove_all(args.installdir, args.dry_run)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
