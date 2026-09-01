#!/usr/bin/env python3
"""
ESA Linux Security + Privilege Escalation Audit
Author: Joshua Keough
"""

import paramiko
import ipaddress
import socket
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ============== CONFIG ==============
username = input("Enter SSH username (prefer domain/admin account): ")
password = getpass.getpass("Enter SSH password: ")
subnet = "192.168.0.0/24"
exclusions = ["192.168.0.1", "192.168.0.255"]
TIMEOUT = 5
MAX_THREADS = 10
LOG_FILE = "ESA_linux_security_audit.txt"
# ====================================

BANNER = r"""
 
                                                   
             ______   _____
            |  ____| / ____|    /\
            | |__   | (___     /  \
            |  __|   \___ \   / /\ \
            | |____  ____) | / ____ \
            |______||_____/ /_/    \_\



        .:~~--__                __--~~:.
      ,:;'~'-,__~~--..,---..--~~__,-`~`::.
    ,:;'        ''-,_ (. .)_,-``        `::.
  ,;'                \ `\)/                `:.
 '                    `--'                    `

                                                  
"""

def run_ssh(client, command, timeout=20):
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err
    except Exception as e:
        return "", str(e)

def check_host(host, username, password):
    results = [f"\n===== {host} ====="]
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password, timeout=TIMEOUT)

        # ----- Identity / Kernel / VM detection -----
        out, _ = run_ssh(client, r"""
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo -n "VM Detection: "
if [ -f /sys/class/dmi/id/product_name ]; then
    cat /sys/class/dmi/id/product_name 2>/dev/null
elif command -v systemd-detect-virt >/dev/null; then
    systemd-detect-virt 2>/dev/null || echo "physical/unknown"
else
    echo "physical/unknown"
fi
""")
        results.append("[+] Identity / Kernel / VM:\n" + (out or "N/A"))

        # ----- Network interfaces (dual NIC check) -----
        out, _ = run_ssh(client, r"""
echo "=== Network Interfaces ==="
ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo
echo ""
echo "=== IP Addresses ==="
ip -4 addr show 2>/dev/null | grep -E 'inet ' | awk '{print $2, $NF}'
""")
        results.append("[+] Network Interfaces (look for dual NICs):\n" + (out or "N/A"))

        # ----- Baseline security services -----
        out, _ = run_ssh(client, r"""
echo -n "auditd: "; systemctl is-active auditd 2>/dev/null || echo "not found"
echo -n "USBGuard: "; systemctl is-active usbguard 2>/dev/null || echo "not found"
echo -n "SELinux: "; getenforce 2>/dev/null || echo "N/A"
""")
        results.append("[+] Core Security Services:\n" + (out or "N/A"))

        # ----- Firewall – actual rules (firewalld + ufw + fallback) -----
        out, _ = run_ssh(client, r"""
echo "=== firewalld ==="
if systemctl is-active firewalld >/dev/null 2>&1; then
    firewall-cmd --list-all 2>/dev/null || echo "firewalld active but cannot list rules"
else
    echo "firewalld not active"
fi
echo ""
echo "=== ufw ==="
if command -v ufw >/dev/null; then
    ufw status verbose 2>/dev/null || echo "ufw present but status failed"
else
    echo "ufw not installed"
fi
echo ""
echo "=== iptables / nftables (fallback) ==="
iptables -L -n 2>/dev/null | head -30 || nft list ruleset 2>/dev/null | head -30 || echo "no iptables/nft rules visible"
""")
        results.append("[+] Firewall Rules:\n" + (out or "N/A"))

        # ----- LUKS -----
        out, _ = run_ssh(client, "lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT")
        if "luks" in out.lower() or "crypto_LUKS" in out:
            results.append("[+] LUKS: Encrypted device(s) found\n" + out)
        else:
            results.append("[+] LUKS: No encrypted devices found\n" + (out or "N/A"))

        # ----- GRUB password + age -----
        grub_cmd = r"""
FILE=""
SOURCE=""
if [ -f /boot/grub2/user.cfg ]; then
    FILE=/boot/grub2/user.cfg
    SOURCE="user.cfg (grub2)"
elif [ -f /boot/grub/user.cfg ]; then
    FILE=/boot/grub/user.cfg
    SOURCE="user.cfg"
fi
if [ -n "$FILE" ]; then
    if grep -qi 'GRUB2_PASSWORD' "$FILE"; then
        MOD_TIME=$(stat -c %Y "$FILE")
        CURRENT_TIME=$(date +%s)
        DAYS=$(( (CURRENT_TIME - MOD_TIME) / 86400 ))
        echo "CONFIGURED|$DAYS|$SOURCE"
    else
        echo "NOT_CONFIGURED|$SOURCE"
    fi
else
    if grep -qi 'password_pbkdf2' /boot/grub*/grub.cfg 2>/dev/null; then
        FILE=$(ls /boot/grub*/grub.cfg 2>/dev/null | head -n 1)
        MOD_TIME=$(stat -c %Y "$FILE")
        CURRENT_TIME=$(date +%s)
        DAYS=$(( (CURRENT_TIME - MOD_TIME) / 86400 ))
        echo "CONFIGURED|$DAYS|grub.cfg"
    else
        echo "NOT_FOUND"
    fi
fi
"""
        out, _ = run_ssh(client, grub_cmd)
        if out.startswith("CONFIGURED"):
            _, days, source = out.split("|")
            results.append(f"[+] GRUB Password: Configured ({days} days since last update, source: {source})")
        elif out.startswith("NOT_CONFIGURED"):
            _, source = out.split("|")
            results.append(f"[+] GRUB Password: File exists but password not set (source: {source})")
        else:
            results.append("[+] GRUB Password: NOT configured or not found")

        # ----- SUID / SGID / Capabilities (focused, low noise) -----
        out, _ = run_ssh(client, r"""
echo '=== SUID ==='
find /usr /bin /sbin /opt /home /root /etc /tmp /var /srv -perm -4000 -type f 2>/dev/null | head -60
echo '=== SGID ==='
find /usr /bin /sbin /opt /etc /tmp /var -perm -2000 -type f 2>/dev/null | head -30
echo '=== Capabilities ==='
getcap -r /usr /bin /sbin /opt 2>/dev/null | head -30 || echo 'getcap unavailable'
""")
        results.append("[+] SUID / SGID / Capabilities:\n" + (out or "N/A"))

        # ----- Cron + weak permissions -----
        out, _ = run_ssh(client, r"""
echo '=== System crontab & cron directories ==='
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
echo '=== User crontabs ==='
crontab -l 2>/dev/null
sudo crontab -l 2>/dev/null
echo '=== Writable cron-related files ==='
find /etc/cron* /var/spool/cron -type f \( -writable -o -perm -0002 \) 2>/dev/null | head -30
""")
        results.append("[+] Cron + weak permissions:\n" + (out or "N/A"))

        # ----- File & Folder Permissions -----
        out, _ = run_ssh(client, r"""
echo '=== World/group writable sensitive files ==='
find /etc /usr/local /opt /lib /lib64 /var/www -type f \( -perm -0002 -o -perm -0020 \) ! -user root 2>/dev/null | head -35
echo '=== Writable systemd unit files ==='
find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' 2>/dev/null | while read f; do
  [ -w "$f" ] && echo "WRITABLE UNIT: $f"
done | head -15
echo '=== Common application folders with loose perms ==='
for d in /opt /usr/local /var/www /srv; do
  [ -d "$d" ] && find "$d" -maxdepth 3 -type d -perm -0002 2>/dev/null | head -10
done
echo '=== Writable PATH directories (hijack risk) ==='
echo $PATH | tr ':' '\n' | while read d; do
  [ -d "$d" ] && [ -w "$d" ] && echo "WRITABLE PATH: $d"
done
""")
        results.append("[+] File & Folder Permissions:\n" + (out or "N/A"))

        # ----- Credentials & Secrets (fixed – catches both assignments and loose keywords) -----
        out, _ = run_ssh(client, r"""
echo '=== Possible plaintext secrets (structured assignments) ==='
grep -rI -E --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.xml' \
  --include='*.yml' --include='*.yaml' --include='*.env' --include='*.sh' --include='*.txt' \
  --include='*.py' --include='*.php' --include='*.js' --include='*.json' --include='*.properties' \
  '(password|passwd|pwd|secret|token|api[_-]?key|db_pass|mysql_pwd|connectionstring)\s*[=:]\s*["\x27]?[^"\x27\s]{3,}' \
  /etc /opt /usr/local /var/www /tmp /root /home 2>/dev/null | head -30

echo ''
echo '=== Loose keyword hits (password / secret / token etc.) ==='
grep -rI -i --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.xml' \
  --include='*.yml' --include='*.yaml' --include='*.env' --include='*.sh' --include='*.txt' \
  --include='*.py' --include='*.php' --include='*.js' --include='*.json' \
  -e 'password' -e 'secret' -e 'token' -e 'api_key' -e 'apikey' \
  /etc /opt /usr/local /var/www /tmp /root 2>/dev/null | head -60 || true
""")
        results.append("[+] Credentials & Secrets:\n" + (out or "None obvious in scoped locations"))

        client.close()
    except (paramiko.ssh_exception.NoValidConnectionsError, socket.timeout):
        results.append("Connection failed: Timeout / no valid connections")
    except Exception as e:
        results.append(f"Connection failed: {e}")
    return "\n".join(results)

def get_hosts(subnet, exclusions):
    net = ipaddress.ip_network(subnet)
    excl = set(ipaddress.ip_address(ip) for ip in exclusions)
    return [str(ip) for ip in net.hosts() if ip not in excl]

def log_results(content):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"\n\n=== ESA Linux Security + PrivEsc Audit: {ts} ===\n")
        f.write(content)
        f.write("\n")

def main():
    print("\033[94m" + BANNER + "\033[0m")
    print("ESA Linux Security + Privilege Escalation Audit")
    print("Baseline security checks + focused priv-esc / misconfiguration checks\n")

    hosts = get_hosts(subnet, exclusions)
    all_results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_host, h, username, password): h for h in hosts}
        for fut in as_completed(futures):
            res = fut.result()
            print(res)
            all_results.append(res)
    log_results("\n".join(all_results))
    print(f"\n[+] Results saved to {LOG_FILE}")

if __name__ == "__main__":
    main()
