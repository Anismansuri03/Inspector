# 🛡️ Inspector

**What was that command window that just flashed and disappeared?**

Inspector is a local-only Windows investigation tool for short-lived processes —
the popups you never get a chance to read. A background Windows Service records
Sysmon process events (command line, parent process, hashes, lifetime),
correlates them with autostart entries, and turns the capture into a console
summary and an interactive HTML report with heuristic risk scoring.

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg) ![Version](https://img.shields.io/badge/version-v2.0.0-orange.svg) ![Build & Release](https://github.com/Anismansuri03/Inspector/actions/workflows/build.yml/badge.svg?branch=main)

> **Not antivirus.** Inspector does not detect, block, or remove malware — risk
> scores are investigation leads, not verdicts. Use it alongside antivirus/EDR,
> not instead of them.

<!-- SCREENSHOT AREA — drop in later, no redesign needed.
     1. inspector-report.png        → hero image, replace the box below with:
        <img src="docs/screenshots/inspector-report.png" alt="Inspector report" width="900">
     2. inspector-console.png       → console summary (place in Usage)
     3. inspector-investigation.png → event detail: hashes, signer, parent chain (place in Usage)
     4. inspector-compare.png       → autostart baseline diff (place in Usage/Compare)
-->
<table>
  <tr>
    <td align="center" width="900">
      <strong>Screenshot incoming</strong><br>
      <code>docs/screenshots/inspector-report.png</code>
    </td>
  </tr>
</table>

| Design principle | What it means |
|---|---|
| **Local-first** | No telemetry · no cloud backend · no phone-home |
| **Investigation-focused** | Short-lived processes · command lines · parent processes · persistence |
| **Heuristic, not verdict** | Risk scores are investigation leads, not malware verdicts |
| **Sysmon-powered** | Kernel-level process create/terminate events — recorded even when a process lives only milliseconds |

---

## What Inspector Does

Inspector answers three questions about startup activity: **what ran**,
**what launched it**, and **whether it matters**. It consumes Sysmon process
events through a Windows Service, correlates each capture with persistence
locations, scores it 0–100 with plain-English reasons, and writes everything
locally as `capture.jsonl` plus an HTML report — nothing leaves the machine.

## Why It Exists

Startup popups disappear too fast to read, and nothing in Windows ties a
two-hundred-millisecond console window back to the scheduled task or Run key
that launched it. Inspector closes that gap **after the fact**: every captured
event keeps its full command line, parent chain, file hashes, signature status,
and exact lifetime, linked to its likely trigger — so you investigate what
happened instead of guessing.

## Key Capabilities

- **Flash-process capture** — Sysmon create/terminate pairs give exact
  lifetime; processes living only a fraction of a second are recorded
- **Autostart correlation** — Run keys, Startup folders, scheduled tasks, WMI
  subscriptions, Winlogon, services, AppInit DLLs, browser/Office add-ins; each
  event linked to its likely trigger
- **Heuristic scoring** — 0–100 with plain-English reasons; known-benign
  patterns and trusted publishers are marked
- **Interactive HTML report** — timeline, search and filter, hashes,
  parent-process chain, remediation notes, autostart inventory
- **Baseline diffing** — save an autostart snapshot, diff it later to see which
  startup entries are new
- **Windows Service** — event-driven (reacts to Sysmon events, no polling);
  `-Activate` / `-Deactivate` control it

---

## Quick Start

Run from an **elevated (Administrator) PowerShell** — the script requires it.

```powershell
# 1. One-time setup: build Inspector and register the Windows Service
.\Inspector.ps1 -Install

# 2. Start watching (auto-starts at future boots until -Deactivate)
.\Inspector.ps1 -Activate

# 3. When something flashes: console summary + HTML report
.\Inspector.ps1 -Report
```

The HTML report opens automatically in your browser. Prefer double-clicking?
Run `Install-Inspector.bat` as administrator — same install flow, with
prerequisite checks (admin rights, .NET SDK, execution policy, Sysmon).

## Requirements

- **Windows 10/11** (or Server 2016+) · **PowerShell 5.1+** · **Administrator session**
- **.NET 8 SDK** — `-Install` builds the service and report from source
  ([download](https://dotnet.microsoft.com/download/dotnet/8.0))
- **Sysmon** — the process-event source Inspector consumes
  ([download](https://learn.microsoft.com/sysinternals/downloads/sysmon))

Release archives include prebuilt `InspectorService`/`InspectorReport`
binaries and a `.sha256` checksum — verify downloads with
`Get-FileHash -Algorithm SHA256 Inspector-v2.zip`.

---

## Installation

**1. Install Sysmon (once per machine)** — Inspector ships a tuned config
(process create + terminate only, common Windows noise filtered out):

```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# Or Sysmon's own defaults
.\Sysmon64.exe -accepteula -i
```

Download Sysmon from https://learn.microsoft.com/sysinternals/downloads/sysmon

**2. Install Inspector:**

```powershell
.\Inspector.ps1 -Install
```

Checks for Sysmon first (stops with the download link if no `Sysmon*` service
exists), then:

1. Builds `InspectorService` into `InspectorService\bin\publish`
2. Builds `InspectorReport`
3. Registers the `InspectorService` Windows Service (start type *Manual* until
   you `-Activate`)
4. Writes a default `config.json` to `C:\ProgramData\Inspector\`

**3. Activate monitoring:**

```powershell
.\Inspector.ps1 -Activate
```

The service starts now and auto-starts at every future boot until you `-Deactivate`.

---

## Usage

### Generate a report

```powershell
# Console summary + interactive HTML report (opens in browser)
.\Inspector.ps1 -Report

# Don't open the browser
.\Inspector.ps1 -Report -NoOpen

# Time filter: last 24 hours / last 7 days / since a date
.\Inspector.ps1 -Report -Since "24h"
.\Inspector.ps1 -Report -Since "7d"
.\Inspector.ps1 -Report -Since "2024-01-01"

# Export instead of (or alongside) the HTML report
.\Inspector.ps1 -Report -Export report.json
.\Inspector.ps1 -Report -Export report.csv -Format csv

# Only flash processes (lifetime under 5 seconds)
.\Inspector.ps1 -Report -FlashOnly

# One machine-readable line for scripts:
#   captured=12;investigate=3;autostart=41
.\Inspector.ps1 -Report -Quiet

# Autostart baseline: save now, diff later
.\Inspector.ps1 -Report -CompareSave
.\Inspector.ps1 -Report -Compare
```

`-Compare` writes a `compare_*.html` diff (added/removed/changed startup
entries) next to the saved baseline, both in `C:\ProgramData\Inspector\`.

### Check status

```powershell
.\Inspector.ps1 -Status
```

Shows service state, start type, log directory, capture size and last update,
archived logs, retention period, and configured target count.

### Stop monitoring

```powershell
.\Inspector.ps1 -Deactivate
```

Stops the service (no process is running afterwards) and sets its start type
back to *Manual*. Captured data stays where it is; nothing auto-starts at the
next boot until you `-Activate` again.

### Clean old logs

```powershell
.\Inspector.ps1 -Clean
```

Deletes archived `capture_*.jsonl` files older than your configured
`RetentionDays` (default: 30) and prunes old HTML reports, keeping the 10
newest.

### Uninstall

```powershell
.\Inspector.ps1 -Uninstall
```

Removes the Windows Service. Captured logs remain at `C:\ProgramData\Inspector`
until you delete them manually (see Privacy below).

---

## Configuration

Config file: `C:\ProgramData\Inspector\config.json` (created by `-Install`)

```json
{
  "LogDirectory": "C:\\ProgramData\\Inspector",
  "TargetImages": [
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "pwsh.dll",
    "cmd.exe",
    "conhost.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "msiexec.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe"
  ],
  "MaxLogSizeMB": 50,
  "RetentionDays": 30,
  "AutoStart": true,
  "EnableNetworkTracking": false,
  "EnableFileTracking": false
}
```

**Key settings:** `TargetImages` (executables to watch — add any `.exe` and
restart the service), `MaxLogSizeMB` (rotation threshold, default 50),
`RetentionDays` (archive lifetime for `-Clean`, default 30). `AutoStart`,
`EnableNetworkTracking`, and `EnableFileTracking` are reserved and currently
unused — start/stop is controlled by `-Activate`/`-Deactivate`.

After editing, restart the service:

```powershell
.\Inspector.ps1 -Deactivate
.\Inspector.ps1 -Activate
```

---

## AI-Assisted Investigation

Every HTML report includes a **Copy Analysis Prompt** button. The prompt is
built **entirely in your browser** and copied to your clipboard — Inspector
makes no network requests and never sends anything to an AI provider.

1. Click **"Copy Analysis Prompt"** in the HTML report
2. Optionally upload the HTML file to ChatGPT, Claude, or any AI assistant
3. Paste the prompt and get a plain-English read of the captured activity

Your data leaves your machine only if *you* choose to share it. Treat AI
output as an opinion to verify, not a verdict.

---

## Privacy & Local-First Design

**What is collected** (while the service is active):

- Sysmon process-create / process-terminate events for the watched executables
  (PowerShell, CMD, script hosts, LOLBins): image path, command line, current
  directory, PID, user, integrity level, parent process, file hashes,
  publisher/signature status, version metadata, timestamps
- A local inventory of autostart entries (Run keys, Startup folders, scheduled
  tasks, WMI subscriptions, Winlogon, services, AppInit DLLs, add-ins)

**Where it is stored:** `C:\ProgramData\Inspector\` on your machine —
`capture.jsonl` (raw events), generated HTML reports, snapshots/baselines, and
`config.json`. Nothing is written anywhere else.

**Does it leave your machine? No.** Inspector contains no network code — no
telemetry, no phone-home, no update checks, no external API calls. Reports and
AI prompts are generated entirely locally. Data can leave your machine only if
*you* manually share a report file or paste a prompt into a third-party
service.

**Treat captures as sensitive:** command lines can contain paths and secrets
that appeared on screen — review reports before sharing them.

**How to delete everything:**

```powershell
.\Inspector.ps1 -Uninstall                              # remove the Windows Service
Remove-Item C:\ProgramData\Inspector -Recurse -Force    # delete all captures and reports
```

To remove old logs only, run `.\Inspector.ps1 -Clean`.

---

## Troubleshooting

**"Sysmon service not found"** — install Sysmon first:

```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

**"No captures yet"** — check that Sysmon is running
(`Get-Service Sysmon64`), check `.\Inspector.ps1 -Status`, then make sure a
watched process actually launched (reboot or open PowerShell manually) and
re-run `.\Inspector.ps1 -Report`.

**"PowerShell execution policy is blocking this script"** — run once, as
Administrator:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**"InspectorReport isn't built yet"** — run `.\Inspector.ps1 -Install` first.

**Not capturing a process you expect** — add its name to `TargetImages` in
`C:\ProgramData\Inspector\config.json`, then `-Deactivate` and `-Activate`.

---

## Architecture

```
Sysmon (Event IDs 1 & 5, Microsoft-Windows-Sysmon/Operational)
      │  real-time events
      ▼
InspectorService.exe (Windows Service)
      │  writes one JSON line per event
      ▼
C:\ProgramData\Inspector\capture.jsonl   (+ config.json, reports, snapshots)
      ▲  reads
      │
InspectorReport.exe  (launched by .\Inspector.ps1 -Report)
      │  scans autostart, scores, correlates
      ▼
console summary + interactive HTML report (written and opened locally)
```

**Components:** **InspectorService** consumes Sysmon events and appends JSON
lines to `capture.jsonl` (rotating/pruning); **InspectorReport** merges
captures, scans autostart, scores, and exports HTML/JSON/CSV; **Inspector.ps1**
installs, activates, reports, cleans, and uninstalls.

Full details: [ARCHITECTURE.md](ARCHITECTURE.md). Tests:
`Invoke-Pester -Script .\tests\Inspector.Tests.ps1` (Windows PowerShell 5.1,
in-box Pester 3.4).

---

## Contributing

Issues and pull requests are welcome. For larger changes, open an issue first.
Build/test steps and PR expectations: [CONTRIBUTING.md](CONTRIBUTING.md).
Please preserve what makes this tool trustworthy: local-only operation, no
telemetry, no unnecessary dependencies, and honest documentation.

## Security

Found a security issue? Please report it **privately** — see
[SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

## License

MIT License — see [LICENSE](LICENSE).

**Credits:** [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
by Microsoft Sysinternals (Inspector is not affiliated with Microsoft) ·
**Spectre.Console** for the terminal UI · built with .NET 8.
