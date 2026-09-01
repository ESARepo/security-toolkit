# ESA Security Toolkit

A multi-platform security assessment and privilege escalation audit toolkit. This repository contains automated scripts designed to scan subnets and evaluate the security posture of both Linux and Windows environments.

## 📋 Features

### Linux Audit (`linpesa.py`)
Written in Python 3, this script connects via SSH to audit Linux hosts for:
* **System Identity:** Hostname, kernel version, and VM detection.
* **Network & Security Services:** Dual NIC detection, `auditd`, `USBGuard`, and `SELinux` status.
* **Firewall Configuration:** Active rules for `firewalld`, `ufw`, and `iptables`.
* **Privilege Escalation Vectors:** SUID/SGID binaries, capabilities, and writable cron jobs.
* **Storage & Encryption:** LUKS encrypted devices and GRUB password configuration age.
* **Data Security:** Weak file/folder permissions and a scoped search for plaintext secrets.

### Windows Audit (`winpesa.ps1`)
Written in PowerShell, this script uses WinRM / PowerShell Remoting to audit Windows hosts for:
* **System Identity:** OS version, build details, domain status, and uptime.
* **Defensive Features:** Windows Defender status, BitLocker encryption, and Secure Boot.
* **Access Control:** Local Administrators group membership and UAC policy configurations.
* **Privilege Escalation Vectors:** Unquoted service paths, writable service binaries, and scheduled tasks.
* **Environment Security:** PowerShell execution policy and language mode.
* **Data Security:** Sensitive directories with weak permissions and auto-logon credentials.

---

## 🚀 Getting Started

### 🐧 Running the Linux Audit

#### Prerequisites
The Linux audit script requires Python 3 and the `paramiko` library for SSH connections.

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the script:
   ```bash
   python3 linpesa.py
   ```
3. Enter your admin/domain SSH credentials when prompted. Results will display on the screen and save to `ESA_linux_security_audit.txt`.

---

### 🪟 Running the Windows Audit

#### Prerequisites
* Must be run from a Windows machine with network visibility to targets over TCP 5985/5986.
* Requires PowerShell 5.1 or higher.
* Target machines must have WinRM enabled.
* **WinRM TrustedHosts Configuration:** Before running the script, you must configure your local machine to trust the target network IPs. Open a PowerShell console as an Administrator and execute one of the following:

  *To trust a specific subnet:*
  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.0.*" -Force
  ```
  *To trust all hosts (recommended for isolated/air-gapped analysis environments only):*
  ```powershell
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
  ```

#### Execution
1. Open a PowerShell console as an Administrator.
2. Run the script:
   ```powershell
   .\winpesa.ps1
   ```
3. Enter your administrative credentials when prompted. Results will display in the console and save to `ESA_windows_security_audit.txt`.


---

## ⚙️ Configuration
You can customize the target subnet, thread counts, and asset exclusions directly inside the `CONFIG` section at the top of each script file:

```python
# Example from the Python script config block
subnet = "10.0.0.0/24"
exclusions = []
MAX_THREADS = 10
```

---

## 🔒 Security & Usage Notice
These tools prompt for the target username in plaintext within the session, while securely masking input passwords (via Python `getpass` and PowerShell `-AsSecureString`). The scripts execute highly detailed audits and are strictly intended for **internal administrative use** by authorized security personnel and system administrators. Always ensure you have explicit permission before scanning network subnets.


## 📝 License
This project is licensed under the MIT License - see the LICENSE file for details.
