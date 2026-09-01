#Requires -Version 5.1
<#
.SYNOPSIS
    ESA Windows Security + Privilege Escalation Audit
.DESCRIPTION
    Remote audit of Windows hosts via WinRM / PowerShell Remoting.
    Baseline security checks + focused priv-esc / misconfiguration checks.
.NOTES
    Author: Joshua Keough (adapted for Windows)
    Run from a machine that can reach the targets on TCP 5985/5986.
    Prefer a domain account with local admin rights on the targets.
#>

# ============== CONFIG ==============
$Username = Read-Host "Enter username (prefer domain\admin or .\localadmin)"
$SecurePass = Read-Host "Enter password" -AsSecureString
$Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePass)

$Subnet = "10.0.0.0/24"
$Exclusions = @()
$TimeoutSec = 5
$MaxThreads = 10
$LogFile = "ESA_windows_security_audit.txt"
$MaxScanTimeMinutes = 3  # Force-kills hung background tasks after 3 minutes total
# ====================================

$Banner = @"

                                                   
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

"@

function Get-HostsFromCidr {
    param([string]$Cidr, [string[]]$Exclude)
    $network = [IPAddress]::Parse(($Cidr -split '/')[0])
    $prefix = [int]($Cidr -split '/')[1]
    $bytes = $network.GetAddressBytes()
    [Array]::Reverse($bytes)
    $start = [BitConverter]::ToUInt32($bytes, 0)
    $count = [Math]::Pow(2, 32 - $prefix) - 2
    $list = @()
    for ($i = 1; $i -le $count; $i++) {
        $ipBytes = [BitConverter]::GetBytes($start + $i)
        [Array]::Reverse($ipBytes)
        $ip = [IPAddress]::new($ipBytes).ToString()
        if ($Exclude -notcontains $ip) { $list += $ip }
    }
    return $list
}

# ================= MAIN =================
Clear-Host
Write-Host $Banner -ForegroundColor Cyan
Write-Host "ESA Windows Security + Privilege Escalation Audit" -ForegroundColor Cyan
Write-Host "Baseline security checks + focused priv-esc / misconfiguration checks`n"

$hosts = Get-HostsFromCidr -Cidr $Subnet -Exclude $Exclusions
Write-Host "Scanning $($hosts.Count) hosts in $Subnet ...`n"

# Convert SecureString for job compatibility (Windows PowerShell 5.1)
$EncryptedPassword = $SecurePass | ConvertFrom-SecureString

$allResults = @()
$jobs = @()

foreach ($h in $hosts) {
    # Throttle
    while ((Get-Job -State Running).Count -ge $MaxThreads) {
        Start-Sleep -Milliseconds 400
    }

    $jobs += Start-Job -ScriptBlock {
        param($ComputerName, $Username, $EncryptedPassword)

        $SecurePass = $EncryptedPassword | ConvertTo-SecureString
        $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePass)

        try {
            $result = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param($TargetIP)

                $results = @()
                $results += "`n===== $env:COMPUTERNAME ($TargetIP) ====="

                # ----- Identity / OS / Domain / VM -----
                try {
                    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                    $vm = if ($cs.Model -match 'Virtual|VMware|Hyper-V|KVM|Xen|QEMU|VirtualBox') { $cs.Model } else { "Physical / Unknown" }

                    $results += "[+] Identity / OS / Domain / VM:"
                    $results += "Hostname : $env:COMPUTERNAME"
                    $results += "OS : $($os.Caption) $($os.Version) (Build $($os.BuildNumber))"
                    $results += "Domain : $($cs.Domain) (PartOfDomain: $($cs.PartOfDomain))"
                    $results += "Manufacturer : $($cs.Manufacturer)"
                    $results += "Model : $($cs.Model)"
                    $results += "VM Detection : $vm"
                    $results += "Last Boot : $($os.LastBootUpTime)"
                    $results += "Uptime (days) : $([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1))"
                } catch {
                    $results += "[+] Identity: Failed - $_"
                }

                # ----- Network Interfaces -----
                try {
                    $results += "`n[+] Network Interfaces (look for dual NICs / unexpected adapters):"
                    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
                        $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress -join ', '
                        $results += " $($_.Name) | $($_.InterfaceDescription) | MAC: $($_.MacAddress) | IP: $ip"
                    }
                } catch {
                    $results += "[+] Network: Failed - $_"
                }

                # ----- Core Security Services / Features -----
                try {
                    $results += "`n[+] Core Security Services / Features:"

                    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($mp) {
                        $results += " Windows Defender Real-time : $($mp.RealTimeProtectionEnabled)"
                        $results += " Antivirus Enabled : $($mp.AntivirusEnabled)"
                        $results += " Antispyware Enabled : $($mp.AntispywareEnabled)"
                        $results += " Last Quick Scan : $($mp.QuickScanEndTime)"
                    } else {
                        $results += " Windows Defender : Not available / disabled"
                    }

                    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                    $fw | ForEach-Object {
                        $results += " Firewall ($($_.Name)) : Enabled=$($_.Enabled) DefaultInbound=$($_.DefaultInboundAction)"
                    }

                    $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue
                    if ($bl) {
                        $bl | ForEach-Object {
                            $results += " BitLocker $($_.MountPoint) : ProtectionStatus=$($_.ProtectionStatus) VolumeStatus=$($_.VolumeStatus)"
                        }
                    } else {
                        $results += " BitLocker : Not available or no volumes"
                    }

                    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                    $results += " Secure Boot : $sb"

                    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
                    if ($dg) {
                        $results += " Credential Guard : $($dg.SecurityServicesRunning -contains 1)"
                        $results += " HVCI / Memory Integrity : $($dg.SecurityServicesRunning -contains 2)"
                    }
                } catch {
                    $results += "[+] Security Services: Partial failure - $_"
                }

                # ----- Local Administrators -----
                try {
                    $results += "`n[+] Local Administrators group:"
                    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | ForEach-Object {
                        $results += " $($_.Name) ($($_.ObjectClass))"
                    }
                } catch {
                    $results += "[+] Local Admins: Failed (may need elevation) - $_"
                }

                # ----- Scheduled Tasks -----
                try {
                    $results += "`n[+] Scheduled Tasks (look for writable actions / high-priv authors):"
                    Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object -First 40 | ForEach-Object {
                        $actions = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
                        $results += " $($_.TaskName) | $($_.TaskPath) | RunAs: $($_.Principal.UserId) | $actions"
                    }
                } catch {
                    $results += "[+] Scheduled Tasks: Failed - $_"
                }

                # ----- Services - Unquoted / Writable -----
                try {
                    $results += "`n[+] Services - Unquoted Path / Writable Binary check (classic priv-esc):"
                    Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.StartMode -ne 'Disabled' } | ForEach-Object {
                        $path = $_.PathName -replace '"',''
                        
                        # Fix: Ignore service binaries located inside C:\Windows\System32 to eliminate background noise
                        if ($path -like "*\System32\*") {
                            return
                        }

                        if ($path -match '^(\S+\s+\S+)' -and $path -notmatch '^".*"') {
                            $results += " UNQUOTED: $($_.Name) -> $path"
                        }
                        $exe = ($path -split ' ')[0]
                        if (Test-Path $exe) {
                            $acl = Get-Acl $exe -ErrorAction SilentlyContinue
                            $writable = $acl.Access | Where-Object {
                                ($_.FileSystemRights -match 'Write|FullControl|Modify') -and
                                ($_.IdentityReference -match 'Everyone|Users|Authenticated Users')
                            }
                            if ($writable) {
                                $results += " WRITABLE BINARY: $($_.Name) -> $exe"
                            }
                        }
                    }
                } catch {
                    $results += "[+] Services: Failed - $_"
