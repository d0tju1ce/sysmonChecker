# Sysmon detection rules – sysmonChecker

File: `config\sysmon\sysmonconfig.xml` · Sysmon schema **4.90** (Sysmon 15.x and Sysmon built into Windows 11) · **323 rules**

## Source (what the configuration is based on)

The configuration is **not copied 1:1 from any public template**. It was created in this project as a custom
configuration (prepared by the AI assistant Claude); its structure and choice of detections are inspired by
the most widely used community configurations:

| Inspiration | What the configuration takes from it (as an idea, not verbatim) |
|---|---|
| **SwiftOnSecurity / sysmon-config** – <https://github.com/SwiftOnSecurity/sysmon-config> | the "include what matters / exclude noise" principle for each event type, network connections logged only for LOLBin tools and programs from user folders, the list of registry keys used for persistence, exclusion of Windows and Defender noise |
| **Olaf Hartong / sysmon-modular** – <https://github.com/olafhartong/sysmon-modular> | detection of access to LSASS (ProcessAccess), named pipes of known C2 frameworks and PsExec, focus on MITRE ATT&CK techniques |
| **Microsoft Sysinternals – Sysmon documentation** – <https://learn.microsoft.com/sysinternals/downloads/sysmon> | schema 4.90, the newer event types 26–29 (FileDeleteDetected, FileBlock*, FileExecutableDetected), condition syntax |

> ⚠ The rules have not been compared with the current versions of the projects above and have not yet been loaded
> into Sysmon (only the XML has been validated). On a PC with Sysmon, load and check them with
> **Settings → Apply configuration to Sysmon** in the application (as administrator) or with
> `sysmon -c config\sysmon\sysmonconfig.xml`. For production use on many workstations, consider using
> the maintained projects above directly.

## Filtering principle

- `onmatch="include"` – an event is logged only if it matches **any** rule (a whitelist of what we want to see).
- `onmatch="exclude"` – **everything except** the events matching the rules is logged (exceptions for noise).
- If an event type has both groups, **the exceptions take precedence**.
- `<Rule groupRelation="and">` – all conditions inside must match at the same time.
- The `image` condition compares only the file name (e.g. `powershell.exe` without the path).
- Exceptions (exclude) use full paths only, never the bare file name or a user-writable folder alone – otherwise a
  renamed or dropped malicious program (e.g. `%TEMP%\MsMpEng.exe`) would be hidden by the exception.

## Summary by event type

| Event ID | Event | Mode | What is logged | Typical techniques (MITRE ATT&CK) |
|---|---|---|---|---|
| 1 | Process Create | all except exceptions | every process start (without Windows/Defender/Sysmon noise) | T1059 Command and Scripting Interpreter, T1204 User Execution |
| 2 | File creation time changed | include + exceptions | file time changes in user profiles, ProgramData, Temp | T1070.006 Timestomp |
| 3 | Network connection | include + exceptions | connections of LOLBin/scripting tools and programs from user folders, ports RDP/SSH/WinRM/VNC/Tor/4444 | T1071 C2, T1105 Ingress Tool Transfer, T1021 Remote Services |
| 5 | Process terminated | include | termination of processes from user profiles, ProgramData, Temp | – |
| 6 | Driver loaded | all except exceptions | drivers that are **not** validly signed by Microsoft | T1068 / BYOVD, T1014 Rootkit |
| 7 | Image loaded | include + exceptions | DLLs from Temp/ProgramData/Public, libraries used for credential theft (vaultcli, samlib, dbghelp, comsvcs), .NET in Office, PowerShell in non-standard processes | T1055 Injection, T1003 Credential Dumping, T1059.001 |
| 8 | CreateRemoteThread | all except exceptions | remote threads outside system processes | T1055 Process Injection |
| 9 | RawAccessRead | all except exceptions | direct disk reads (except the system, VSS, defrag, Defender) | T1003.002/003 (NTDS, SAM) |
| 10 | ProcessAccess | include + exceptions | access to LSASS and winlogon, suspicious masks (0x1FFFFF, 0x1F3FFF, 0x143A), CallTrace with dbghelp/dbgcore/UNKNOWN | T1003.001 LSASS Memory |
| 11 | FileCreate | include + exceptions | executables, scripts, ISO/VHD, macro documents, dumps, Startup, scheduled tasks, drivers, PS profiles | T1547 Autostart, T1053 Scheduled Task, T1566 Phishing |
| 12–14 | Registry | include + exceptions | Run keys, services, IFEO, Winlogon, AppInit, LSA, COM, Office; weakening of defences (Defender, AMSI, firewall, RDP, UAC, WDigest) | T1547.001, T1543.003, T1546.012, T1562 Impair Defenses |
| 15 | FileCreateStreamHash | include | files downloaded from the internet (Zone.Identifier) in Downloads/Temp/Outlook, executables and archives | T1105, T1564.004 ADS |
| 17–18 | Pipe created/connected | include + exceptions | known pipes of Cobalt Strike, PsExec/PAExec/RemCom, Mimikatz; pipes of processes from user folders | T1021.002 SMB/Admin Shares, T1570 |
| 19–21 | WMI events | all | WMI filters, consumers and bindings | T1546.003 WMI Event Subscription |
| 22 | DNS query | all except exceptions | DNS queries except Microsoft, Office and certificate authority domains | T1071.004 DNS, T1568 Dynamic Resolution |
| 23 | FileDelete (archived) | **disabled** | – (ID 26 is used instead, without archiving files) | – |
| 24 | Clipboard change | **disabled** | – (privacy) | – |
| 25 | Process tampering | all except exceptions | process hollowing / herpaderping (without browsers) | T1055.012 Process Hollowing |
| 26 | FileDeleteDetected | include + exceptions | deletion of executables, scripts, dumps and .evtx logs | T1070.004 File Deletion |
| 27–28 | FileBlock* | **disabled** | – (blocking could break legitimate software) | – |
| 29 | FileExecutableDetected | include + exceptions | a new executable in user profiles, ProgramData, Temp, PerfLogs | T1105, T1036 Masquerading |

sysmonChecker highlights events 4, 6, 8, 10, 16, 19, 20, 21, 25, 27, 28, 29 and 255 in the table as suspicious (few events, strong signal: Sysmon stopped or reconfigured, drivers, remote threads, LSASS access, WMI persistence, tampering, executables). Above the AI group limit they are sent first, process access (10) after the others.

## All rules (generated from the XML)

### Event ID 1 – ProcessCreate

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | is | `C:\Windows\Sysmon64.exe` |
| Image | is | `C:\Windows\Sysmon.exe` |
| Image | is | `C:\Windows\System32\Sysmon.exe` |
| CommandLine | begin with | `C:\Windows\system32\wermgr.exe -upload` |
| CommandLine | is | `C:\Windows\system32\SppExtComObj.Exe -Embedding` |
| CommandLine | begin with | `C:\Windows\system32\DllHost.exe /Processid` |
| CommandLine | begin with | `\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1` |
| ParentImage | is | `C:\Windows\System32\CompatTelRunner.exe` |
| Image | is | `C:\Windows\System32\backgroundTaskHost.exe` |
| Image | is | `C:\Windows\System32\RuntimeBroker.exe` |
| Image | is | `C:\Windows\System32\SearchProtocolHost.exe` |
| Image | is | `C:\Windows\System32\SearchFilterHost.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| Image | is | `C:\Program Files\Windows Defender\MpCmdRun.exe` |

### Event ID 2 – FileCreateTime

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetFilename | begin with | `C:\Users\` |
| TargetFilename | begin with | `C:\ProgramData\` |
| TargetFilename | begin with | `C:\Windows\Temp\` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | end with | `\AppData\Local\Microsoft\OneDrive\OneDrive.exe` |
| Image | is | `C:\Program Files\Microsoft OneDrive\OneDrive.exe` |
| Image | is | `C:\Windows\System32\msiexec.exe` |
| Image | is | `C:\Windows\SysWOW64\msiexec.exe` |
| Image | is | `C:\Windows\servicing\TrustedInstaller.exe` |
| Image | is | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| Image | is | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` |
| Image | is | `C:\Program Files\Mozilla Firefox\firefox.exe` |

### Event ID 3 – NetworkConnect

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| Image | image | `powershell.exe` |
| Image | image | `pwsh.exe` |
| Image | image | `cmd.exe` |
| Image | image | `wscript.exe` |
| Image | image | `cscript.exe` |
| Image | image | `mshta.exe` |
| Image | image | `rundll32.exe` |
| Image | image | `regsvr32.exe` |
| Image | image | `certutil.exe` |
| Image | image | `bitsadmin.exe` |
| Image | image | `msbuild.exe` |
| Image | image | `installutil.exe` |
| Image | image | `regasm.exe` |
| Image | image | `regsvcs.exe` |
| Image | image | `msiexec.exe` |
| Image | image | `cmstp.exe` |
| Image | image | `odbcconf.exe` |
| Image | image | `hh.exe` |
| Image | image | `curl.exe` |
| Image | image | `wmic.exe` |
| Image | image | `at.exe` |
| Image | image | `schtasks.exe` |
| Image | image | `notepad.exe` |
| Image | image | `psexec.exe` |
| Image | image | `psexesvc.exe` |
| Image | image | `ftp.exe` |
| Image | image | `tftp.exe` |
| Image | image | `nc.exe` |
| Image | image | `ncat.exe` |
| Image | image | `python.exe` |
| Image | image | `java.exe` |
| Image | begin with | `C:\Users\` |
| Image | begin with | `C:\ProgramData\` |
| Image | begin with | `C:\Windows\Temp\` |
| Image | contains | `\Downloads\` |
| DestinationPort | is | `22` |
| DestinationPort | is | `23` |
| DestinationPort | is | `3389` |
| DestinationPort | is | `5800` |
| DestinationPort | is | `5900` |
| DestinationPort | is | `5985` |
| DestinationPort | is | `5986` |
| DestinationPort | is | `4444` |
| DestinationPort | is | `1337` |
| DestinationPort | is | `9001` |
| DestinationPort | is | `9030` |
| DestinationPort | is | `9050` |
| DestinationPort | is | `9150` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | end with | `\AppData\Local\Microsoft\OneDrive\OneDrive.exe` |
| Image | end with | `\AppData\Local\Microsoft\Teams\current\Teams.exe` |
| Image | end with | `\AppData\Local\Programs\Microsoft VS Code\Code.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| DestinationHostname | end with | `.microsoft.com` |
| DestinationHostname | end with | `.windowsupdate.com` |

### Event ID 5 – ProcessTerminate

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| Image | begin with | `C:\Users\` |
| Image | begin with | `C:\Windows\Temp\` |
| Image | begin with | `C:\ProgramData\` |

### Event ID 6 – DriverLoad

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| *combination* | and | Signature *is* `Microsoft Windows` **and** SignatureStatus *is* `Valid` |
| *combination* | and | Signature *is* `Microsoft Corporation` **and** SignatureStatus *is* `Valid` |
| *combination* | and | Signature *is* `Microsoft Windows Hardware Compatibility Publisher` **and** SignatureStatus *is* `Valid` |

### Event ID 7 – ImageLoad

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| ImageLoaded | contains | `\AppData\Local\Temp\` |
| ImageLoaded | begin with | `C:\Users\Public\` |
| ImageLoaded | begin with | `C:\Windows\Temp\` |
| ImageLoaded | begin with | `C:\ProgramData\` |
| ImageLoaded | end with | `\vaultcli.dll` |
| ImageLoaded | end with | `\samlib.dll` |
| ImageLoaded | end with | `\dbghelp.dll` |
| ImageLoaded | end with | `\dbgcore.dll` |
| ImageLoaded | end with | `\comsvcs.dll` |
| *combination* | and | Image *end with* `\WINWORD.EXE` **and** ImageLoaded *end with* `\clr.dll` |
| *combination* | and | Image *end with* `\EXCEL.EXE` **and** ImageLoaded *end with* `\clr.dll` |
| ImageLoaded | end with | `\System.Management.Automation.dll` |
| ImageLoaded | end with | `\System.Management.Automation.ni.dll` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| *combination* | and | Image *is* `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` **and** ImageLoaded *contains* `\System.Management.Automation` |
| *combination* | and | Image *is* `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` **and** ImageLoaded *contains* `\System.Management.Automation` |
| *combination* | and | Image *is* `C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe` **and** ImageLoaded *contains* `\System.Management.Automation` |
| *combination* | and | Image *is* `C:\Program Files\PowerShell\7\pwsh.exe` **and** ImageLoaded *contains* `\System.Management.Automation` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| Image | is | `C:\Program Files\Windows Defender\MsMpEng.exe` |

### Event ID 8 – CreateRemoteThread

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| SourceImage | is | `C:\Windows\System32\csrss.exe` |
| SourceImage | is | `C:\Windows\System32\wininit.exe` |
| SourceImage | is | `C:\Windows\System32\winlogon.exe` |
| SourceImage | is | `C:\Windows\System32\services.exe` |
| SourceImage | is | `C:\Windows\System32\dwm.exe` |
| SourceImage | is | `C:\Windows\System32\audiodg.exe` |
| SourceImage | is | `C:\Windows\System32\wbem\WmiPrvSE.exe` |
| SourceImage | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |

### Event ID 9 – RawAccessRead

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | is | `System` |
| Image | is | `C:\Windows\System32\svchost.exe` |
| Image | is | `C:\Windows\System32\wininit.exe` |
| Image | is | `C:\Windows\System32\autochk.exe` |
| Image | is | `C:\Windows\System32\VSSVC.exe` |
| Image | is | `C:\Windows\System32\defrag.exe` |
| Image | is | `C:\Windows\System32\SearchIndexer.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |

### Event ID 10 – ProcessAccess

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetImage | is | `C:\Windows\system32\lsass.exe` |
| TargetImage | is | `C:\Windows\system32\winlogon.exe` |
| GrantedAccess | is | `0x1FFFFF` |
| GrantedAccess | is | `0x1F3FFF` |
| GrantedAccess | is | `0x143A` |
| CallTrace | contains | `dbghelp.dll` |
| CallTrace | contains | `dbgcore.dll` |
| CallTrace | contains | `UNKNOWN(` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| SourceImage | is | `C:\Windows\system32\wininit.exe` |
| SourceImage | is | `C:\Windows\system32\csrss.exe` |
| SourceImage | is | `C:\Windows\system32\lsm.exe` |
| SourceImage | is | `C:\Windows\system32\services.exe` |
| SourceImage | is | `C:\Windows\system32\wbem\wmiprvse.exe` |
| SourceImage | is | `C:\Windows\system32\taskmgr.exe` |
| SourceImage | is | `C:\Windows\Sysmon64.exe` |
| SourceImage | is | `C:\Windows\Sysmon.exe` |
| SourceImage | is | `C:\Windows\System32\Sysmon.exe` |
| SourceImage | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| GrantedAccess | is | `0x1000` |
| GrantedAccess | is | `0x400` |

### Event ID 11 – FileCreate

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetFilename | contains | `\Start Menu\Programs\Startup\` |
| TargetFilename | begin with | `C:\Windows\System32\Tasks\` |
| TargetFilename | begin with | `C:\Windows\Tasks\` |
| TargetFilename | begin with | `C:\Windows\System32\drivers\` |
| TargetFilename | begin with | `C:\Windows\System32\GroupPolicy\` |
| TargetFilename | contains | `\Microsoft\Windows\PowerShell\` |
| TargetFilename | end with | `\WindowsPowerShell\profile.ps1` |
| TargetFilename | end with | `Microsoft.PowerShell_profile.ps1` |
| TargetFilename | end with | `.exe` |
| TargetFilename | end with | `.dll` |
| TargetFilename | end with | `.sys` |
| TargetFilename | end with | `.ps1` |
| TargetFilename | end with | `.psm1` |
| TargetFilename | end with | `.bat` |
| TargetFilename | end with | `.cmd` |
| TargetFilename | end with | `.vbs` |
| TargetFilename | end with | `.vbe` |
| TargetFilename | end with | `.js` |
| TargetFilename | end with | `.jse` |
| TargetFilename | end with | `.wsf` |
| TargetFilename | end with | `.hta` |
| TargetFilename | end with | `.scr` |
| TargetFilename | end with | `.lnk` |
| TargetFilename | end with | `.iso` |
| TargetFilename | end with | `.img` |
| TargetFilename | end with | `.vhd` |
| TargetFilename | end with | `.vhdx` |
| TargetFilename | end with | `.application` |
| TargetFilename | end with | `.appref-ms` |
| TargetFilename | end with | `.docm` |
| TargetFilename | end with | `.xlsm` |
| TargetFilename | end with | `.pptm` |
| TargetFilename | end with | `.dmp` |
| TargetFilename | end with | `.kirbi` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | is | `C:\Windows\System32\TiWorker.exe` |
| Image | is | `C:\Windows\servicing\TrustedInstaller.exe` |
| Image | is | `C:\Windows\System32\msiexec.exe` |
| Image | is | `C:\Windows\SysWOW64\msiexec.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| Image | is | `C:\Program Files\Windows Defender\MsMpEng.exe` |
| TargetFilename | begin with | `C:\Windows\SoftwareDistribution\` |
| TargetFilename | begin with | `C:\Windows\WinSxS\` |
| TargetFilename | begin with | `C:\Windows\assembly\NativeImages_` |
| TargetFilename | begin with | `C:\Windows\Microsoft.NET\Framework` |
| *combination* | and | Image *contains* `\Microsoft\OneDrive\` **and** TargetFilename *contains* `\AppData\Local\Microsoft\OneDrive\` |

### Event ID 12–14 – RegistryEvent

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetObject | contains | `\CurrentVersion\Run` |
| TargetObject | contains | `\CurrentVersion\Policies\Explorer\Run` |
| TargetObject | contains | `\CurrentVersion\Explorer\User Shell Folders\Startup` |
| TargetObject | contains | `\CurrentVersion\Explorer\Shell Folders\Startup` |
| TargetObject | contains | `\CurrentVersion\Winlogon\Userinit` |
| TargetObject | contains | `\CurrentVersion\Winlogon\Shell` |
| TargetObject | contains | `\CurrentVersion\Winlogon\Notify` |
| TargetObject | contains | `\CurrentVersion\Windows\AppInit_DLLs` |
| TargetObject | contains | `\CurrentVersion\Image File Execution Options\` |
| TargetObject | contains | `\CurrentVersion\SilentProcessExit\` |
| TargetObject | contains | `\CurrentControlSet\Control\Session Manager\BootExecute` |
| TargetObject | contains | `\CurrentControlSet\Control\Session Manager\AppCertDlls` |
| TargetObject | contains | `\CurrentControlSet\Control\Lsa\` |
| TargetObject | contains | `\CurrentControlSet\Control\SecurityProviders` |
| TargetObject | contains | `\CurrentControlSet\Control\NetworkProvider\Order` |
| TargetObject | contains | `\CurrentControlSet\Control\Print\Monitors\` |
| TargetObject | end with | `\ImagePath` |
| TargetObject | end with | `\ServiceDll` |
| TargetObject | end with | `\Parameters\ServiceDll` |
| TargetObject | contains | `\Software\Classes\CLSID\` |
| TargetObject | contains | `\Environment\UserInitMprLogonScript` |
| TargetObject | contains | `\Microsoft\Windows\CurrentVersion\Group Policy\Scripts` |
| TargetObject | contains | `\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` |
| TargetObject | contains | `\Microsoft\Office\` |
| TargetObject | contains | `\Microsoft\Windows Defender\` |
| TargetObject | contains | `\Policies\Microsoft\Windows Defender\` |
| TargetObject | contains | `\Microsoft\AMSI\Providers\` |
| TargetObject | contains | `\Services\SharedAccess\Parameters\FirewallPolicy\` |
| TargetObject | contains | `\Control\Terminal Server\fDenyTSConnections` |
| TargetObject | contains | `\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber` |
| TargetObject | contains | `\Control\SecurityProviders\WDigest\UseLogonCredential` |
| TargetObject | contains | `\Policies\System\EnableLUA` |
| TargetObject | contains | `\Policies\System\LocalAccountTokenFilterPolicy` |
| TargetObject | contains | `\Services\EventLog\` |
| TargetObject | contains | `\Services\SysmonDrv\` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | is | `C:\Windows\System32\svchost.exe` |
| Image | is | `C:\Windows\servicing\TrustedInstaller.exe` |
| Image | is | `C:\Windows\System32\TiWorker.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| Image | is | `C:\Program Files\Windows Defender\MsMpEng.exe` |
| TargetObject | end with | `\Microsoft\Windows Defender\Signature Updates` |
| TargetObject | contains | `\Microsoft\Office\16.0\Common\` |
| TargetObject | contains | `\Microsoft\Office\ClickToRun\` |
| EventType | is | `CreateKey` |

### Event ID 15 – FileCreateStreamHash

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetFilename | contains | `\Downloads\` |
| TargetFilename | contains | `\Temp\` |
| TargetFilename | contains | `\Content.Outlook\` |
| TargetFilename | end with | `.exe` |
| TargetFilename | end with | `.dll` |
| TargetFilename | end with | `.ps1` |
| TargetFilename | end with | `.hta` |
| TargetFilename | end with | `.vbs` |
| TargetFilename | end with | `.js` |
| TargetFilename | end with | `.iso` |
| TargetFilename | end with | `.zip` |

### Event ID 17–18 – PipeEvent

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| PipeName | begin with | `\msagent_` |
| PipeName | begin with | `\MSSE-` |
| PipeName | begin with | `\postex_` |
| PipeName | begin with | `\status_` |
| PipeName | begin with | `\win_svc` |
| PipeName | begin with | `\ntsvcs` |
| PipeName | begin with | `\scerpc` |
| PipeName | begin with | `\PSEXESVC` |
| PipeName | begin with | `\RemCom` |
| PipeName | begin with | `\paexec` |
| PipeName | begin with | `\csexec` |
| PipeName | contains | `\lsadump` |
| PipeName | contains | `\cachedump` |
| PipeName | contains | `\wceservicepipe` |
| PipeName | contains | `\isapi_http` |
| PipeName | contains | `\isapi_dg` |
| PipeName | contains | `\jaccdpqnvbrrxlaf` |
| PipeName | contains | `\winsession` |
| PipeName | contains | `\DserNamePipe` |
| Image | begin with | `C:\Users\` |
| Image | begin with | `C:\ProgramData\` |
| Image | begin with | `C:\Windows\Temp\` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | end with | `\AppData\Local\Microsoft\OneDrive\OneDrive.exe` |
| Image | end with | `\AppData\Local\Programs\Microsoft VS Code\Code.exe` |
| PipeName | begin with | `\mojo.` |
| PipeName | begin with | `\crashpad_` |

### Event ID 19–21 – WmiEvent

**Everything is logged** (empty `onmatch="exclude"` filter).

### Event ID 22 – DnsQuery

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| QueryName | is | `localhost` |
| QueryName | end with | `.local` |
| QueryName | end with | `.arpa` |
| QueryName | end with | `.lan` |
| QueryName | end with | `.microsoft.com` |
| QueryName | end with | `.windowsupdate.com` |
| QueryName | end with | `.windows.com` |
| QueryName | is | `login.windows.net` |
| QueryName | end with | `.msftncsi.com` |
| QueryName | end with | `.msedge.net` |
| QueryName | end with | `.office.com` |
| QueryName | end with | `.office.net` |
| QueryName | end with | `.office365.com` |
| QueryName | end with | `.live.com` |
| QueryName | end with | `.bing.com` |
| QueryName | end with | `.digicert.com` |
| QueryName | end with | `.globalsign.com` |
| QueryName | end with | `.sectigo.com` |
| QueryName | end with | `.letsencrypt.org` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |

### Event ID 23 – FileDelete

**Disabled** – nothing is logged (empty `onmatch="include"` filter).

### Event ID 24 – ClipboardChange

**Disabled** – nothing is logged (empty `onmatch="include"` filter).

### Event ID 25 – ProcessTampering

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | begin with | `C:\Program Files\Mozilla Firefox\` |
| Image | begin with | `C:\Program Files\Google\Chrome\` |
| Image | begin with | `C:\Program Files (x86)\Microsoft\Edge\` |

### Event ID 26 – FileDeleteDetected

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetFilename | end with | `.exe` |
| TargetFilename | end with | `.dll` |
| TargetFilename | end with | `.sys` |
| TargetFilename | end with | `.ps1` |
| TargetFilename | end with | `.bat` |
| TargetFilename | end with | `.cmd` |
| TargetFilename | end with | `.vbs` |
| TargetFilename | end with | `.js` |
| TargetFilename | end with | `.hta` |
| TargetFilename | end with | `.dmp` |
| TargetFilename | end with | `.evtx` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | is | `C:\Windows\System32\TiWorker.exe` |
| Image | is | `C:\Windows\servicing\TrustedInstaller.exe` |
| Image | is | `C:\Windows\System32\msiexec.exe` |
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| TargetFilename | begin with | `C:\Windows\SoftwareDistribution\` |
| TargetFilename | begin with | `C:\Windows\WinSxS\` |

### Event ID 27 – FileBlockExecutable

**Disabled** – nothing is logged (empty `onmatch="include"` filter).

### Event ID 28 – FileBlockShredding

**Disabled** – nothing is logged (empty `onmatch="include"` filter).

### Event ID 29 – FileExecutableDetected

**Log if any rule matches (include):**

| Field | Condition | Value |
|---|---|---|
| TargetFilename | begin with | `C:\Users\` |
| TargetFilename | begin with | `C:\ProgramData\` |
| TargetFilename | begin with | `C:\Windows\Temp\` |
| TargetFilename | begin with | `C:\Perflogs\` |

**Exceptions – do not log (exclude):**

| Field | Condition | Value |
|---|---|---|
| Image | begin with | `C:\ProgramData\Microsoft\Windows Defender\Platform\` |
| *combination* | and | Image *contains* `\Microsoft\OneDrive\` **and** TargetFilename *contains* `\AppData\Local\Microsoft\OneDrive\` |

