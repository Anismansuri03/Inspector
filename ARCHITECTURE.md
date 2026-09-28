# Inspector v2 - Architecture

Inspector is a three-project .NET 8 solution plus a thin PowerShell control layer.
This document describes every data source, scoring heuristic, and output format.

## Project layout

| Project | Type | Responsibility |
|---|---|---|
| `Inspector.Common` | Class library | Shared `CaptureRecord` / `MergedEvent` data model |
| `InspectorService` | Windows Service | Real-time Sysmon subscriber, writes `capture.jsonl` |
| `InspectorReport` | Console app | Reads captures, scans autostart, scores risk, emits report |
| `Inspector.ps1` | PowerShell | Install/activate/compare/export CLI wrapper |

## Autostart sources scanned

Every source below is enumerated by `AutostartScanner.ScanAll()`.

### 1. Run / RunOnce keys
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`

### 2. Startup folders
- Per-user: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- Common: `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`

### 3. Scheduled Tasks
Enumerated via the Task Scheduler COM API (`Schedule.Service`).
Includes tasks with **Logon**, **Boot**, or **Startup** triggers whose action
references a shell/script host (`powershell`, `pwsh`, `cmd.exe`, `wscript`,
`cscript`, `mshta`). The full task XML is stored as the command for auditing.

### 4. WMI permanent event consumers
`root\subscription` namespace, `CommandLineEventConsumer` class.
These are a classic persistence vector because they fire without a visible
scheduled task or Run key.

### 5. Winlogon values
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `Shell` (expected: `explorer.exe`)
- `Userinit` (expected: `C:\Windows\system32\userinit.exe`)

### 6. Win32_StartupCommand (WMI)
The same set Task Manager / msconfig shows under "Startup", retrieved in one
WMI query. Includes name, full command, location, and user.

### 7. Automatic services
`Win32_Service` where `StartMode = 'Auto'`. Included when the `PathName`
points at a shell/script host **or** the binary lives outside the trusted
folders (Program Files / System32). The scorer notes that AV/update services
may legitimately appear here.

## Risk scoring

`RiskScorer` assigns each entry an integer 0-100 plus a bucket:

| Bucket | Score | Meaning |
|---|---|---|
| low | 0-29 | Likely benign |
| medium | 30-59 | Worth a look |
| high | 60-100 | Investigate |

Scoring is additive; every contributing reason is kept in a list so the report
can explain *why* something was flagged.

### Command-line indicators (each +25)
- `-EncodedCommand`, `-enc`, `-e`
- `IEX`, `Invoke-Expression`
- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Invoke-RestMethod`
- `WebClient`, `Net.WebClient`, `FromBase64String`
- `-nop`, `-w hidden`, `Hidden`, `Bypass`, `-ExecutionPolicy Bypass`
- `Reflection.Assembly`, `Start-Process`, `bitsadmin`, `certutil -urlcache`

### Base64 blobs (+25)
Any run of >= 80 consecutive base64-alphabet characters with no whitespace.

### Shell host launch (+15)
Command's image path resolves to `powershell` / `pwsh` / `cmd` / `wscript` /
`cscript` / `mshta`.

### Path heuristics
- Suspicious folder (`\temp\`, `\appdata\`, `\programdata\`, `\users\public\`,
  `\downloads\`, recycle bin): **+30**
- Non-standard folder (not System32 / Program Files / Start Menu): **+15**

### Publisher
- Microsoft / Google / Mozilla / Adobe: no penalty
- Other named third-party publisher: **+5**
- No publisher info at all: **+20**

### File age (process captures only)
- Created in last 7 days: **+25**
- Created in last 30 days: **+10**

### Process-specific
- Shell launched by another shell: **+10**

## Capture pipeline (InspectorService)

1. Subscribes to `Microsoft-Windows-Sysmon/Operational` with XPath
   `*[System[(EventID=1 or EventID=5)]]` - only ProcessCreate and ProcessTerminate.
2. Filters to the target image list (see `Worker.TargetImages`).
3. Serializes a `CaptureRecord` to one JSON line per event.
4. Appends to `C:\ProgramData\Inspector\capture.jsonl` under a lock.
5. Auto-rotates at **50 MB** to `capture_yyyyMMdd_HHmmss.jsonl`.

The report reads **all** `capture*.jsonl` files with a 3-attempt retry
(200/400/600 ms backoff) so it never crashes while the service is writing.

## Output formats

### Console (default)
Color-coded Spectre table: risk badge, heuristic score, full local timestamp,
process, lifetime, likely trigger. Top 25 rows, with an explicit
"Showing 25 of N" note when truncated.

### `--quiet`
Single line: `captured=N;investigate=N;autostart=N` - designed for scripts.

### HTML
Self-contained single-file dashboard with system info, risk breakdown,
frequency stats, date-grouped process cards, and a full autostart inventory.

### `--json <path>` / `--csv <path>`
Structured export alongside the normal report (`JsonExporter` / `CsvExporter`)
- events, autostart, scores, reasons, system metadata. JSON is a stable shape
  for tooling; CSV is two sections (events then autostart), each with its own
  header, opening directly in Excel/Sheets.

### `--export <path> [--format json|csv]`
Export-only mode: writes the file and exits without console table or HTML.

### `--since <value>` / `--flash-only`
Time filter (`24h`, `7d`, or an ISO date) and lifetime filter
(`< 5000 ms`) applied before scoring and rendering.

## Compare mode

```powershell
.\Inspector.ps1 -Report -CompareSave     # baseline -> baseline.snapshot.json
# ... install software / make changes ...
.\Inspector.ps1 -Report -Compare         # diff -> compare_*.html
```

Direct exe equivalents:

```text
InspectorReport.exe --snapshot                          # snapshot_*.json
InspectorReport.exe --compare-save                      # baseline.snapshot.json
InspectorReport.exe --compare-show                      # baseline vs current
InspectorReport.exe --compare before.json after.json [--out diff.html]
```

Snapshots are JSON files of the scored autostart inventory. The diff reports
**Added / Removed / Changed (command differs) / Unchanged** and renders both a
console summary and an HTML diff.

## Security posture

- **No network calls.** Inspector never phones home. All scoring is local.
- **No code execution of scanned entries.** Commands are read as strings only.
- Release binaries should be SHA256-published alongside downloads; consider
  code-signing `InspectorService.exe` / `InspectorReport.exe` for wider rollout.
- Execution-policy guidance is surfaced by `Inspector.ps1` when blocked.

## Tests

`tests/Inspector.Tests.ps1` - Pester 3.4 compatible (Windows PowerShell 5.1).
Covers the pure scoring helpers and capture-fixture JSON parsing:

```powershell
Invoke-Pester -Script .\tests\Inspector.Tests.ps1
```

## Extending

- **New autostart source:** add a `Scan*()` method returning
  `List<AutostartEntry>` and append it in `AutostartScanner.ScanAll()`.
- **New scoring signal:** add a sub-scorer in `RiskScorer` and call it from
  `ScoreProcess` / `ScoreAutostart`, appending reasons so they surface in the UI.
- **New watched process:** edit `Worker.TargetImages` in InspectorService and
  rebuild (`.\Inspector.ps1 -Install`).
