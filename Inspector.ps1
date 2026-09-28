#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Control layer for Inspector v2 (Sysmon-backed Windows Service edition).

.USAGE
    .\Inspector.ps1 -Install      # one-time: build + register the Windows Service
    .\Inspector.ps1 -Activate     # start watching
    .\Inspector.ps1 -Deactivate   # stop watching, free memory
    .\Inspector.ps1 -Status       # is it currently active?
    .\Inspector.ps1 -Report       # console summary + opens the HTML deep-dive report
    .\Inspector.ps1 -Clean        # clean up old log files
    .\Inspector.ps1 -Uninstall    # remove the service entirely

.REPORT OPTIONS
    .\Inspector.ps1 -Report                           # console + HTML (default)
    .\Inspector.ps1 -Report -NoOpen                   # console + HTML, don't open browser
    .\Inspector.ps1 -Report -Export report.json       # export to JSON
    .\Inspector.ps1 -Report -Export report.csv -Format csv  # export to CSV
    .\Inspector.ps1 -Report -Since "24h"              # only show last 24 hours
    .\Inspector.ps1 -Report -Since "2024-01-01"       # only show since date
    .\Inspector.ps1 -Report -FlashOnly                # show only flash processes (< 5s lifetime)
    .\Inspector.ps1 -Report -CompareSave              # save current autostart as baseline
    .\Inspector.ps1 -Report -Compare                  # diff current vs saved baseline
#>

param(
    [switch]$Install,
    [switch]$Activate,
    [switch]$Deactivate,
    [switch]$Status,
    [switch]$Report,
    [switch]$Clean,
    [switch]$Uninstall,
    [string]$Export,
    [string]$Format = "json",
    [string]$Since = "",
    [switch]$NoOpen,
    [switch]$FlashOnly,
    [switch]$CompareSave,
    [switch]$Compare,
    [switch]$Quiet
)

# --- Execution Policy Check ---
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -eq 'Restricted' -or $currentPolicy -eq 'AllSigned') {
    Write-Host "`n[ERROR] PowerShell execution policy is blocking this script." -ForegroundColor Red
    Write-Host "  Current policy : $currentPolicy" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To fix this, run the following command ONCE in PowerShell (as Admin):" -ForegroundColor Cyan
    Write-Host "    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor White
    Write-Host ""
    Write-Host "  This is a one-time setup. After that, Inspector (and other local scripts) will work." -ForegroundColor Gray
    Write-Host "  No need to run it again.`n" -ForegroundColor Gray
    exit 1
}

$RootDir     = $PSScriptRoot
$ServiceName = "InspectorService"
$ServiceProj = Join-Path $RootDir "InspectorService"
$ReportProj  = Join-Path $RootDir "InspectorReport"
$PublishDir  = Join-Path $RootDir "InspectorService\bin\publish"
$ReportExe   = Join-Path $RootDir "InspectorReport\bin\Release\net8.0-windows\InspectorReport.exe"
$ServiceExe  = Join-Path $PublishDir "InspectorService.exe"

# Configuration
$LogDir = "C:\ProgramData\Inspector"
$ConfigFile = Join-Path $LogDir "config.json"

function Invoke-Install {
    Write-Host "`n== Checking Sysmon ==" -ForegroundColor Cyan
    Write-Host "  Looking for Sysmon service..."

    if (-not (Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue)) {
        Write-Host "  [ERROR] Sysmon service not found." -ForegroundColor Red
        Write-Host "  Install it from https://learn.microsoft.com/sysinternals/downloads/sysmon" -ForegroundColor Yellow
        return
    }
    Write-Host "  [OK] Sysmon found." -ForegroundColor Green

    Write-Host "`n== Building InspectorService ==" -ForegroundColor Cyan
    Write-Host "  Using .NET 8 SDK..."
    dotnet publish $ServiceProj -c Release -o $PublishDir 2>&1 | ForEach-Object { Write-Host "    $_" }
    if (-not (Test-Path $ServiceExe)) {
        Write-Host "  [ERROR] Build failed." -ForegroundColor Red
        return
    }
    Write-Host "  [OK] InspectorService built successfully." -ForegroundColor Green

    Write-Host "`n== Building InspectorReport ==" -ForegroundColor Cyan
    dotnet build $ReportProj -c Release 2>&1 | ForEach-Object { Write-Host "    $_" }
    if (-not (Test-Path $ReportExe)) {
        Write-Host "  [ERROR] Build failed." -ForegroundColor Red
        return
    }
    Write-Host "  [OK] InspectorReport built successfully." -ForegroundColor Green

    Write-Host "`n== Registering Windows Service ==" -ForegroundColor Cyan
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "  Service already registered." -ForegroundColor Yellow
    } else {
        New-Service -Name $ServiceName -BinaryPathName "`"$ServiceExe`"" `
            -DisplayName "Inspector Watcher" -StartupType Manual `
            -Description "Watches Sysmon for suspicious PowerShell/CMD activity at logon (Inspector tool)." | Out-Null
        Write-Host "  [OK] Service registered." -ForegroundColor Green
    }

    # Create default config if it doesn't exist
    if (-not (Test-Path $ConfigFile)) {
        Write-Host "`n== Creating default configuration ==" -ForegroundColor Cyan
        $defaultConfig = @{
            LogDirectory = $LogDir
            TargetImages = @("powershell.exe", "powershell_ise.exe", "pwsh.exe", "pwsh.dll",
                           "cmd.exe", "conhost.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                           "msiexec.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe")
            MaxLogSizeMB = 50
            RetentionDays = 30
            AutoStart = $true
            EnableNetworkTracking = $false
            EnableFileTracking = $false
        }
        $defaultConfig | ConvertTo-Json -Depth 3 | Set-Content $ConfigFile
        Write-Host "  [OK] Config created at $ConfigFile" -ForegroundColor Green
    }

    Write-Host "`n[SUCCESS] Install complete." -ForegroundColor Green
    Write-Host "  Run '.\Inspector.ps1 -Activate' to start watching.`n" -ForegroundColor Yellow
}

function Invoke-Activate {
    if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        Write-Host "[ERROR] Service not installed. Run '.\Inspector.ps1 -Install' first." -ForegroundColor Red
        return
    }
    Set-Service -Name $ServiceName -StartupType Automatic
    Start-Service -Name $ServiceName
    Write-Host "`n[OK] Inspector is now ACTIVE." -ForegroundColor Green
    Write-Host "  - InspectorService is running, watching Sysmon in real time."
    Write-Host "  - It will also auto-start at every future boot until you -Deactivate."
    Write-Host "`n  When the popup happens, run: .\Inspector.ps1 -Report`n" -ForegroundColor Yellow
}

function Invoke-Deactivate {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Set-Service -Name $ServiceName -StartupType Manual
    }
    Write-Host "`n[OK] Inspector is now INACTIVE." -ForegroundColor Green
    Write-Host "  - Service stopped, no memory/CPU being used."
    Write-Host "  - Captured history is preserved at $LogDir\capture.jsonl"
    Write-Host "  - Won't auto-start at next boot until you -Activate again.`n"
}

function Invoke-Status {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Write-Host "`n== Inspector Status ==" -ForegroundColor Cyan

    if (-not $svc) {
        Write-Host "  Not installed. Run '.\Inspector.ps1 -Install'." -ForegroundColor Yellow
        return
    }

    Write-Host "  Service          : $ServiceName"
    Write-Host "  Display name     : $($svc.DisplayName)"
    Write-Host "  State            : $($svc.Status)" -ForegroundColor $(if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' })
    Write-Host "  Start type       : $($svc.StartType)"
    Write-Host "  Log directory    : $LogDir"

    $captureFile = Join-Path $LogDir "capture.jsonl"
    if (Test-Path $captureFile) {
        $size = (Get-Item $captureFile).Length / 1MB
        $last = (Get-Item $captureFile).LastWriteTime
        Write-Host "  Capture file     : $('{0:N2} MB' -f $size), last updated $last"
    } else {
        Write-Host "  Capture file     : (none yet)"
    }

    # Check for old log files
    $oldLogs = Get-ChildItem -Path $LogDir -Filter "capture_*.jsonl" -ErrorAction SilentlyContinue
    if ($oldLogs) {
        $totalOldSize = ($oldLogs | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "  Archived logs    : $($oldLogs.Count) files, $(('{0:N2} MB' -f $totalOldSize))"
    }

    # Config info
    if (Test-Path $ConfigFile) {
        $config = Get-Content $ConfigFile | ConvertFrom-Json
        Write-Host "  Retention        : $($config.RetentionDays) days"
        Write-Host "  Target processes : $($config.TargetImages.Count) configured"
    }

    Write-Host ""
}

function Invoke-Report {
    if (-not (Test-Path $ReportExe)) {
        Write-Host "[ERROR] InspectorReport isn't built yet. Run '.\Inspector.ps1 -Install' first." -ForegroundColor Red
        return
    }

    # Build report arguments
    $reportArgs = @()
    if ($NoOpen) { $reportArgs += "--no-open" }
    if ($FlashOnly) { $reportArgs += "--flash-only" }
    if ($Export) {
        $reportArgs += "--export"
        $reportArgs += $Export
        if ($Format -ne "json") {
            $reportArgs += "--format"
            $reportArgs += $Format
        }
    }
    if ($Since) {
        $reportArgs += "--since"
        $reportArgs += $Since
    }
    if ($CompareSave) { $reportArgs += "--compare-save" }
    if ($Compare -and -not $CompareSave) { $reportArgs += "--compare-show" }
    if ($Quiet) { $reportArgs += "--quiet" }

    & $ReportExe @reportArgs
}

function Invoke-Clean {
    Write-Host "`n== Cleaning old log files ==" -ForegroundColor Cyan

    if (-not (Test-Path $LogDir)) {
        Write-Host "  Log directory doesn't exist: $LogDir" -ForegroundColor Yellow
        return
    }

    # Load config for retention settings
    $retentionDays = 30
    if (Test-Path $ConfigFile) {
        $config = Get-Content $ConfigFile | ConvertFrom-Json
        $retentionDays = $config.RetentionDays
    }

    Write-Host "  Retention policy : $retentionDays days"
    Write-Host "  Scanning $LogDir..."

    $cutoff = (Get-Date).AddDays(-$retentionDays)
    $oldFiles = Get-ChildItem -Path $LogDir -Filter "capture_*.jsonl" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff }

    if ($oldFiles) {
        $totalSize = ($oldFiles | Measure-Object -Property Length -Sum).Sum
        Write-Host "  Found $($oldFiles.Count) old file(s) to clean up..."

        foreach ($file in $oldFiles) {
            $size = $file.Length / 1KB
            Remove-Item $file.FullName -Force
            Write-Host "    Removed: $($file.Name) ({0:N2} KB)" -f $size -ForegroundColor Gray
        }

        Write-Host "`n[OK] Cleaned up $([Math]::Round($totalSize / 1MB, 2)) MB of old logs." -ForegroundColor Green
    } else {
        Write-Host "  No old log files to clean." -ForegroundColor Gray
    }

    # Also clean up very old HTML reports (keep last 10)
    $htmlFiles = Get-ChildItem -Path $LogDir -Filter "report_*.html" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending

    if ($htmlFiles.Count -gt 10) {
        $toDelete = $htmlFiles | Select-Object -Skip 10
        Write-Host "  Cleaning old HTML reports (keeping last 10)..."
        foreach ($file in $toDelete) {
            Remove-Item $file.FullName -Force
        }
        Write-Host "  Removed $($toDelete.Count) old report(s)." -ForegroundColor Gray
    }

    Write-Host ""
}

function Invoke-Uninstall {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Host "[OK] Service removed." -ForegroundColor Green
    }
    Write-Host "  Captured logs at $LogDir were left in place." -ForegroundColor Gray
    Write-Host "  Run 'Remove-Item $LogDir -Recurse -Force' to delete everything.`n" -ForegroundColor Gray
}

# --- Main dispatch ---
if ($Install)           { Invoke-Install }
elseif ($Activate)      { Invoke-Activate }
elseif ($Deactivate)    { Invoke-Deactivate }
elseif ($Status)        { Invoke-Status }
elseif ($Report)        { Invoke-Report }
elseif ($Clean)         { Invoke-Clean }
elseif ($Uninstall)     { Invoke-Uninstall }
else {
    Write-Host "Inspector v2 - Sysmon-backed Windows Security Monitor"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\Inspector.ps1 -Install       # one-time: build + register the service"
    Write-Host "  .\Inspector.ps1 -Activate      # start watching"
    Write-Host "  .\Inspector.ps1 -Deactivate    # stop watching, free memory"
    Write-Host "  .\Inspector.ps1 -Status        # check current state"
    Write-Host "  .\Inspector.ps1 -Report        # console summary + opens HTML report"
    Write-Host "  .\Inspector.ps1 -Clean         # clean up old log files"
    Write-Host "  .\Inspector.ps1 -Uninstall     # remove the service"
    Write-Host ""
    Write-Host "Report options:"
    Write-Host "  -NoOpen           Don't open HTML in browser"
    Write-Host "  -Export <file>    Export to JSON or CSV"
    Write-Host "  -Format csv       Use CSV format (default: json)"
    Write-Host "  -Since <time>     Filter by time (e.g., '24h', '7d', '2024-01-01')"
    Write-Host "  -FlashOnly        Show only flash processes (< 5 seconds lifetime)"
    Write-Host "  -CompareSave      Save current autostart as baseline"
    Write-Host "  -Compare          Diff current vs saved baseline"
    Write-Host "  -Quiet            Suppress console output"
}