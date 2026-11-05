# sysmonChecker

Portable Windows monitor for **Sysmon**: it shows the state of Sysmon, installs the Sysmon service with the supplied
configuration and lets you browse, filter and analyze the Sysmon events.

- No installation – a single signed exe, requires only .NET Framework 4.8 (part of Windows 10 / 11)
- Runs as the current user; administrator rights only for actions that change Sysmon (UAC on demand)
- Supplied Sysmon configuration with a report before it is applied
- Optional AI analysis of the events (Claude or ChatGPT) with masking of local identities

## Contents

| Path | Description |
|---|---|
| `SysmonChecker-<version>.exe` | the application |
| `config\sysmon\sysmonconfig.xml` | Sysmon configuration (schema 4.90) |
| `docs\Sysmon-Setup-Guide.md` | setting up Sysmon on a new PC |
| `docs\Sysmon-Detection-Rules.md` | overview of the detection rules and their source |
| `assets\` | logo (PNG 256 / 512 / 1024) and the icon |
| `cert\SysmonChecker.cer` | public code signing certificate |
| `src\` | source code (C#, WinForms, .NET Framework 4.8) and build scripts |

## Quick start

1. Copy the folder to the PC – preferably to a folder only administrators can change
   (e.g. `C:\Program Files\sysmonChecker`), not to a share or the Desktop.
2. Start `SysmonChecker-<version>.exe`.
3. If Sysmon is not installed yet: *Settings → Install Sysmon service* (as administrator).

The Sysmon log can be read by administrators and by members of the local group **Event Log Readers** – a user can be
added on the Settings page (once, as administrator; takes effect after signing out and in).

Settings are stored next to the exe in `sysmonChecker.settings.xml`, separately for each computer, so the folder can be
moved as a whole. Changes on the Settings page are saved with **Save settings** and automatically when the application
is closed. Unexpected errors are written to `%LOCALAPPDATA%\sysmonChecker\error.log`.

## Sysmon built into Windows

Windows 11 and Windows Server 2025 include Sysmon as an optional feature. Turning the feature on only adds
`sysmon.exe` – the service and the driver are created by `sysmon -i <config>`; without it there is no Sysmon service,
also after a restart. **Install Sysmon service** does both: enables the feature when needed and installs the service
with the supplied configuration after showing its report. The built-in and the standalone Sysinternals Sysmon cannot
be installed together.

**Apply configuration to Sysmon** shows a report before loading: SHA-256 of the file, number of rules, event types that
are switched off, exclusions that may hide malicious activity and whether the same configuration is already active.

## Pages

| Page | What it does |
|---|---|
| **Overview** | state of Sysmon: service, driver, event log, configuration file |
| **Events** | Sysmon events with filters (Event ID, e.g. `1,3,22` or `!7`, time, process, user, full text), suspicious event types highlighted, event detail, CSV export, AI analyzer, auto-refresh |
| **Event IDs** | overview of the Sysmon event types; a double click opens the events of that ID |
| **Settings** | configuration path, limits, auto-refresh; *Install Sysmon service*, *Apply configuration to Sysmon*, active configuration, log size; access to the Sysmon log; AI analyzer |

## AI analyzer

The **AI analyzer** button sends the selected or shown events to **Claude** (Anthropic API) or **ChatGPT** (OpenAI API)
over HTTPS and shows the analysis: verdict and severity, findings with MITRE ATT&CK IDs, likely benign activity,
recommended actions and configuration tuning suggestions. Follow-up questions continue the conversation;
**Save report** writes it as Markdown.

Setup (*Settings → AI analyzer*):

1. Create an API key at [console.anthropic.com](https://console.anthropic.com) or
   [platform.openai.com](https://platform.openai.com). The API is billed per use; a ChatGPT Plus / Claude Pro
   subscription does not include API access.
2. Paste the key, **Save key**, **Test connection**, choose the model.

The key is stored in the Windows Credential Manager of the current user on this computer – never in the application
folder.

What is sent:

- Identical events are grouped and sent once with a count; GUIDs and similar noise are left out, long values shortened.
- **Masking** (on by default) replaces local identities – computer, domain and user names, internal IP addresses and
  other identifiers – with pseudonyms before sending; the answer is shown with the real values. Paths, command lines,
  hashes, public IPs and domains are sent, the analysis needs them.
- **Secrets** (passwords, tokens, API keys, private keys) are always removed, also from your questions.
- **Preview data** shows exactly what will be sent.

The AI can be wrong – use the answer as a lead for your own investigation. Reports and CSV exports contain events of
this computer; the application warns before saving them into the application folder.

## Digital signature

The exe is signed with a self-signed code signing certificate (SHA-256, RSA 3072, DigiCert timestamp):

| | |
|---|---|
| Subject | `CN=SysmonChecker Code Signing` |
| SHA-1 thumbprint | `3E3393594294EB4F167CC3DDD937DD969FDB27E3` |
| Valid until | 3 Nov 2031 |
| Public certificate | `cert\SysmonChecker.cer` |

```powershell
Get-AuthenticodeSignature .\SysmonChecker-*.exe
(Get-PfxCertificate .\cert\SysmonChecker.cer).Thumbprint   # compare with the thumbprint above
```

Without importing the certificate the status is `UnknownError` (untrusted root). To make Windows report it as
`Valid`, import it once (PowerShell as administrator) – this trusts every program signed with this certificate on
that computer:

```powershell
Import-Certificate -FilePath .\cert\SysmonChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\SysmonChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

## Building from source

Requires the .NET SDK.

| Script | Does |
|---|---|
| `src\build.cmd` | builds `SysmonChecker-<version>.exe` (version from `src\SysmonChecker.csproj`), copies it to the application folder and signs it when a code signing certificate is available |
| `src\make_dist.ps1` | builds the transfer package `dist\SysmonChecker-<version>.zip` (+ `.sha256`) without local data |

## License

MIT – see [LICENSE](LICENSE). The embedded font Nunito Sans is licensed under the SIL Open Font License 1.1
(`src\Fonts\OFL.txt`).
