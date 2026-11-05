# SysmonChecker v. 1.2.0

A portable Windows tool for **running and reviewing Sysmon on a Windows host**. It installs the Sysmon service with a
supplied configuration, shows the state of Sysmon and lets you browse, filter and analyze the Sysmon events.

The supplied configuration (323 rules, schema 4.90) logs what matters for detecting attacks – process starts,
network connections of risky programs, persistence, credential access, defence evasion – and leaves out the noise of
Windows and security products.

## Highlights

- **Sysmon built into Windows supported**: turning the Windows feature on only adds `sysmon.exe` – the app also
  creates the service and the driver.
- **Configuration report** before applying: rules, event types switched off and exclusions that may hide attacks.
- **Portable**: no installation, a single signed exe; settings are kept per computer, so the folder can be moved.
- **Runs as a standard user**: administrator rights (UAC) only for actions that change Sysmon; the Sysmon log can be
  read by members of *Event Log Readers*.
- **Suspicious event types highlighted** (Sysmon stopped, drivers, remote threads, LSASS access, WMI persistence, …).
- **Optional AI analysis** of the events (Claude or ChatGPT) with masking of local identities.

## Requirements

- Windows 10/11 or Windows Server 2016+ (64-bit)
- .NET Framework 4.8 (included in Windows 10 1903+ / Windows 11)
- Sysmon 15.x from Sysinternals, or Sysmon built into Windows 11 / Windows Server 2025
- Administrator rights for installing the service, applying the configuration and reading the log
  (or membership in *Event Log Readers*)

## Download

Download everything at once:

- **ZIP**: on the repository page click **Code → Download ZIP**, or use
  [main.zip](https://github.com/d0tju1ce/sysmonChecker/archive/refs/heads/main.zip).
  Before extracting, unblock the archive (right-click → Properties → **Unblock**), or run:

  ```powershell
  Unblock-File "$env:USERPROFILE\Downloads\sysmonChecker-main.zip"
  ```

- **Git**:

  ```powershell
  git clone https://github.com/d0tju1ce/sysmonChecker.git
  ```

These files must stay together in one folder:

| File | Purpose |
|---|---|
| `SysmonChecker-<version>.exe` | desktop app |
| `config\sysmon\sysmonconfig.xml` | Sysmon configuration |
| `sysmonChecker.settings.xml` | settings of each computer (created automatically) |

Keep the folder where only administrators can change it (e.g. `C:\Program Files\sysmonChecker`), not on the Desktop or
a share – the configuration is loaded into Sysmon with administrator rights.

## Usage

### Installing the Sysmon service

Start `SysmonChecker-<version>.exe`, then **Settings → Install Sysmon service** (as administrator):

- With **Sysmon built into Windows** the feature is enabled when needed (DISM; after a restart click the button again)
  and the service is installed with `sysmon -i` and the supplied configuration.
- With **Sysmon from Sysinternals** see [docs/Sysmon-Setup-Guide.md](docs/Sysmon-Setup-Guide.md).
- The configuration report is shown before anything is installed. Built-in and Sysinternals Sysmon cannot be
  installed together.

### Desktop app

- **Overview** shows the state of Sysmon: service, driver, event log and configuration file.
- **Events** lists the Sysmon events. Filter by Event ID (e.g. `1,3,22` or `!7`), time, process, user and full text.
  Suspicious event types are highlighted; click a row for the event detail. **Export CSV**, **AI analyzer** and
  auto-refresh. Right-click: only this ID / hide this ID / what is this ID.
- **Event IDs** describes the Sysmon event types; a double click opens the events of that ID.
- **Settings**: **Install Sysmon service**, **Apply configuration to Sysmon** (`sysmon -c`, with the configuration
  report), the active configuration, the log size, access to the log (*Event Log Readers*), the AI analyzer.

Settings in `sysmonChecker.settings.xml` (one entry per computer, saved with **Save settings** and when the app is
closed):

| Setting | Meaning |
|---|---|
| `SysmonConfigPath` | Sysmon configuration (found automatically in `config\sysmon`) |
| `MaxEvents` | maximum number of events shown |
| `AutoRefresh`, `RefreshSeconds` | automatic refresh of the events and its interval |

**Apply configuration to Sysmon** shows before loading: the SHA-256 of the file, the number of rules, event types that
are switched off, exclusions that may hide malicious activity (a bare file name, a user-writable folder, a whole drive),
whether standard users can change the file and whether the same configuration is already active.

## AI analyzer

The **AI analyzer** button sends the selected or shown events to **Claude** (Anthropic API) or **ChatGPT** (OpenAI
API) over HTTPS and shows the analysis: verdict and severity, findings with MITRE ATT&CK IDs, likely benign activity,
recommended actions and configuration tuning suggestions. Follow-up questions continue the conversation;
**Save report** writes it as Markdown.

1. Create an API key at [console.anthropic.com](https://console.anthropic.com) or
   [platform.openai.com](https://platform.openai.com). The API is billed per use; a ChatGPT Plus / Claude Pro
   subscription does not include API access.
2. **Settings → AI analyzer**: paste the key, **Save key**, **Test connection**, choose the model.

The key is stored in the Windows Credential Manager of the current user on the computer, never in the app folder.

| What happens to the data | |
|---|---|
| Grouping | identical events are sent once with a count; GUIDs and similar noise are left out, long values shortened |
| Masking (on by default) | local identities (computer, domain and user names, internal IP addresses and other identifiers) are replaced with pseudonyms; the answer is shown with the real values |
| Secrets | passwords, tokens, API keys and private keys are always removed, also from your questions |
| Preview | **Preview data** shows exactly what will be sent |

The AI can be wrong – use the answer as a lead for your own investigation.

## What is detected

| Event ID | Event | What is logged | MITRE ATT&CK |
|---|---|---|---|
| 1 | Process Create | every process start without Windows / Defender / Sysmon noise | T1059, T1204 |
| 2 | File creation time changed | time changes in user profiles, ProgramData, Temp | T1070.006 |
| 3 | Network connection | LOLBin and scripting tools, programs from user folders, RDP / SSH / WinRM / VNC / Tor ports | T1071, T1105, T1021 |
| 6 | Driver loaded | drivers not validly signed by Microsoft | T1068, T1014 |
| 7 | Image loaded | DLLs from Temp / ProgramData, credential theft libraries, .NET in Office | T1055, T1003 |
| 8 | CreateRemoteThread | remote threads outside system processes | T1055 |
| 10 | ProcessAccess | access to LSASS and winlogon, suspicious access masks and call traces | T1003.001 |
| 11 | FileCreate | executables, scripts, ISO / VHD, macro documents, dumps, Startup, scheduled tasks | T1547, T1053, T1566 |
| 12–14 | Registry | Run keys, services, IFEO, Winlogon, LSA, COM; weakening of Defender, AMSI, firewall, RDP, UAC | T1547.001, T1543.003, T1562 |
| 17–18 | Named pipes | pipes of Cobalt Strike, PsExec, Mimikatz and of programs from user folders | T1021.002, T1570 |
| 19–21 | WMI | WMI filters, consumers and bindings | T1546.003 |
| 22 | DNS query | DNS queries except Microsoft, Office and certificate authority domains | T1071.004, T1568 |
| 25 | Process tampering | process hollowing / herpaderping | T1055.012 |
| 26 | FileDeleteDetected | deletion of executables, scripts, dumps and event logs | T1070.004 |
| 29 | FileExecutableDetected | new executables in user profiles, ProgramData, Temp | T1105, T1036 |

The full list of the rules, exclusions and their source is in
[docs/Sysmon-Detection-Rules.md](docs/Sysmon-Detection-Rules.md).

## Configuration

| File | Content |
|---|---|
| `config\sysmon\sysmonconfig.xml` | Sysmon configuration: include / exclude rules per event type |

Exclusions use full paths only, never a bare file name or a user-writable folder alone – a renamed or dropped
malicious program would otherwise be hidden by the exclusion. After editing, apply the file with
**Settings → Apply configuration to Sysmon** (the report shows risky exclusions).

## Digital signature

`SysmonChecker-<version>.exe` is signed with a self-signed certificate:

| | |
|---|---|
| Subject | `CN=SysmonChecker Code Signing` |
| SHA1 thumbprint | `3E3393594294EB4F167CC3DDD937DD969FDB27E3` |
| Valid until | 3 Nov 2031 |
| Public certificate | `cert\SysmonChecker.cer` (the private key is not in the repository) |

Verify the signature:

```powershell
Get-AuthenticodeSignature .\SysmonChecker-*.exe
```

To make Windows report the signature as `Valid`, import the certificate once (PowerShell as administrator):

```powershell
Import-Certificate -FilePath .\cert\SysmonChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\SysmonChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Without the import the status is `UnknownError` (untrusted), but you can still check the thumbprint.

## Building from source

The source code is in `src\`. Run `src\build.cmd`; it needs the .NET SDK. The build compiles the exe, copies it to the
app folder as `SysmonChecker-<version>.exe` (version from `src\SysmonChecker.csproj`), removes older versions and signs
it. Signing is skipped if the code signing certificate is not present.

`src\make_dist.ps1` then builds the distribution package `dist\SysmonChecker-<version>.zip` (+ `.sha256`). It checks the
version and the signature and leaves out local data: `sysmonChecker.settings.xml`, `src\` and `dist\`.

## Known limitations

- The configuration has been validated, but not yet compared with the current versions of the community
  configurations it is inspired by; tune it for your environment.
- The Sysmon log has a fixed size (64 MB by default) – older events are overwritten; enlarge it on the Settings page.
- Event IDs 23 (archived file delete), 24 (clipboard) and 27–28 (file blocking) are disabled on purpose.
- More noise on developer and admin machines (scripts, build tools, RMM).

## Roadmap

- Comparison with the current SwiftOnSecurity / sysmon-modular rules
- Export of events to EVTX / JSON for a SIEM
- Charts of events over time and top processes
- Reading the Sysmon log of a remote computer

## Changelog

### 1.2.0

- **Install Sysmon service**: for Sysmon built into Windows enables the feature when needed and creates the service
  and the driver with the supplied configuration (the feature alone does not create the service).
- The exe carries its version in the name; settings are saved automatically when the app is closed.
- Permission checks include the folders above the app folder.

### 1.1.0

Security and robustness fixes based on a code review.

- Configuration report before **Apply configuration to Sysmon**.
- Links in AI answers open only as http(s) after confirmation; masking of identities and removal of secrets from the
  data and the questions.
- `src\make_dist.ps1` builds a clean distribution ZIP without local data.

### 1.0.0

First public release.

## Sources

- Microsoft Sysinternals: [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) and its documentation
- SwiftOnSecurity: [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) (inspiration)
- Olaf Hartong: [sysmon-modular](https://github.com/olafhartong/sysmon-modular) (inspiration)

## License

The code is licensed under the MIT License (see `LICENSE`). The embedded Nunito Sans font is licensed under the
SIL Open Font License 1.1 (`src\Fonts\OFL.txt`).
