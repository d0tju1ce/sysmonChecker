# Setting up Sysmon on a new PC

This guide describes how to install **Sysmon** (system activity logging) on Windows and how to check it with **sysmonChecker**.

| | |
|---|---|
| **Target system** | Windows 10 / 11 or Windows Server 2016+ (64-bit) |
| **Tested versions** | Sysmon 15.x, Sysmon built into Windows 11 (schema 4.90) |
| **Required rights** | local administrator (installation); a standard user can run the application afterwards |
| **Estimated time** | 10 minutes |

Overview of the detection rules and their source: [Sysmon-Detection-Rules.md](Sysmon-Detection-Rules.md)

---

## 1. Preparation

1. Copy the **`sysmonChecker`** folder to the PC (e.g. to `C:\Tools\sysmonChecker`):

   ```
   sysmonChecker\
   ├─ SysmonChecker-<version>.exe         application for checking Sysmon and browsing its events
   ├─ config\sysmon\sysmonconfig.xml      Sysmon configuration
   └─ docs\                               documentation
   ```

2. If the folder was transferred over the internet, unblock the files (PowerShell **as administrator**):

   ```powershell
   Get-ChildItem "C:\Tools\sysmonChecker" -Recurse | Unblock-File
   ```

3. `SysmonChecker-<version>.exe` requires .NET Framework 4.8 (included in Windows 10 1903+ / Windows 11).

---

## 2. Installing Sysmon

Choose **one** of the options.

### Option A – Sysmon built into Windows 11

Windows 11 (updates from February 2026) and Windows Server 2025 include Sysmon as an optional feature (binary
`C:\Windows\System32\sysmon.exe`, service **Sysmon**). It cannot run next to the standalone Sysinternals Sysmon.

**Enabling the feature only adds the binary – it does not create the Sysmon service. Without step 2 there is no
Sysmon service, also after a restart.**

Easiest: sysmonChecker as administrator → *Settings → Sysmon on this computer → **Install Sysmon service*** – it
enables the feature if needed (DISM) and runs step 2 with the configuration of the application. Manually:

1. *Settings → System → Optional features → More Windows features* → tick **Sysmon**, or:

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Sysmon
   ```

2. Install the service and the driver with the configuration (required, as administrator):

   ```powershell
   sysmon -accepteula -i "C:\Tools\sysmonChecker\config\sysmon\sysmonconfig.xml"
   ```

### Option B – Sysmon from Sysinternals

1. Download <https://learn.microsoft.com/sysinternals/downloads/sysmon> (`Sysmon.zip`) and extract it to `C:\Tools\Sysmon`.
2. Verify the signature (publisher *Microsoft Corporation*):

   ```powershell
   Get-AuthenticodeSignature C:\Tools\Sysmon\Sysmon64.exe | Format-List Status, SignerCertificate
   ```

3. Install it with the configuration:

   ```powershell
   C:\Tools\Sysmon\Sysmon64.exe -accepteula -i "C:\Tools\sysmonChecker\config\sysmon\sysmonconfig.xml"
   ```

   Sysmon copies itself to `C:\Windows\Sysmon64.exe` and registers the **Sysmon64** service and the **SysmonDrv** driver.

> ⚠ Only one Sysmon may run on a PC – do not combine options A and B.

### Recommended – a larger log

The default 64 MB lasts only a short time:

```powershell
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824     # 1 GB
```

The size can also be changed in sysmonChecker: **Settings → Sysmon on this computer → Set log size** (as administrator).

### Optional – reading the log without administrator rights

The Sysmon log can be read by administrators and by members of the local group **Event Log Readers**.
To let a standard user use sysmonChecker without administrator rights, add the user to the group
(once, as administrator), then the user signs out and in again:

```powershell
net localgroup "Event Log Readers" <DOMAIN\user> /add
```

Or in sysmonChecker: **Settings → Access to the Sysmon log → Add to Event Log Readers**. The group has a
translated name in localised Windows (e.g. „Čtenáři protokolu událostí“ in Czech); the application finds it automatically.

---

## 3. Checking with sysmonChecker

1. Start **`SysmonChecker-<version>.exe`**. It runs as the current user; options that change Sysmon need administrator rights
   (**Settings → Restart as administrator**).
2. The **Overview** page must show ✔ **Sysmon is enabled and running**.
3. **Settings → Application** – the *Sysmon configuration (XML)* field is filled in automatically (`config\sysmon\sysmonconfig.xml`).
4. **Settings → Show active Sysmon configuration** (as administrator) confirms that Sysmon uses this configuration.
   *No rules installed* means that no configuration has been loaded yet – use **Apply configuration to Sysmon**.
5. **Events** page → **Load** – events must be displayed.

## 4. Verifying detection (test)

```powershell
Start-Process notepad; Resolve-DnsName example.org | Out-Null
```

The **Events** page shows Event ID **1** *Process Create* (`notepad.exe`) and **22** *DNS query* (`example.org`).

---

## 5. Maintenance

| Task | Procedure |
|---|---|
| Change the configuration | edit `config\sysmon\sysmonconfig.xml` → in the application **Settings → Apply configuration to Sysmon** (= `sysmon -c <xml>`) |
| Exception for a noisy application | add a line to the matching `onmatch="exclude"` section and apply the configuration |
| Update Sysmon (option B) | `Sysmon64.exe -u`, then `-i` again with the new version |

> The configuration loaded into Sysmon and the log size are stored on each PC (registry / Windows settings) –
> they are not copied with the application folder. Apply them on every new PC.

## 6. Troubleshooting

| Symptom | Solution |
|---|---|
| *Access to the Sysmon log was denied* | run the application as administrator, or add the user to **Event Log Readers** (section 2) |
| *Channel … does not exist* | Sysmon is not installed – step 2 |
| Sysmon rejects the configuration (schema error) | update Sysmon to 15.x / a current Windows 11 |
| Many ID 3/11 events from one application | add an `onmatch="exclude"` exception and apply the configuration |

```powershell
Get-Service Sysmon*                                       # service state
sysmon -c                                                 # active configuration (Sysmon64 -c for option B)
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
```

## 7. Uninstalling

```powershell
sysmon -u            # option A (or turn the optional feature off)
Sysmon64.exe -u      # option B
```
