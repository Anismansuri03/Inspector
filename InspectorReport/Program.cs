using System.Text.Json;
using Inspector.Common;
using Inspector.Report;
using Spectre.Console;

var parsed = new ArgsParser(args);
var config = InspectorConfig.Load();

string logDir = config.LogDirectory;
string htmlOut = Path.Combine(logDir, $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
string baselinePath = Path.Combine(logDir, "baseline.snapshot.json");
string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

if (!parsed.Quiet)
{
    AnsiConsole.Write(new Rule("[bold cyan]Inspector Report[/]").LeftJustified());
    AnsiConsole.MarkupLine($"[grey]{DateTime.Now:f}[/]\n");
}

// ---- Compare two snapshot files -------------------------------------------
if (parsed.CompareBefore != null && parsed.CompareAfter != null)
{
    var beforeSnap = SnapshotComparer.Load(parsed.CompareBefore);
    var afterSnap = SnapshotComparer.Load(parsed.CompareAfter);
    var diff = SnapshotComparer.Diff(beforeSnap, afterSnap);

    if (!parsed.Quiet)
    {
        AnsiConsole.MarkupLine("[bold cyan]Startup comparison[/]");
        AnsiConsole.MarkupLine($"[grey]before {beforeSnap.TakenUtc:u}  ->  after {afterSnap.TakenUtc:u}[/]");
        AnsiConsole.WriteLine(SnapshotComparer.RenderConsole(diff));
    }

    string diffHtml = parsed.CompareOut ?? Path.Combine(logDir, $"compare_{stamp}.html");
    Directory.CreateDirectory(logDir);
    File.WriteAllText(diffHtml, SnapshotComparer.RenderHtml(diff));
    if (!parsed.Quiet)
    {
        AnsiConsole.MarkupLine($"\n[grey]Diff HTML:[/] [underline]{diffHtml}[/]");
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(diffHtml) { UseShellExecute = true }); }
        catch { }
    }
    else
    {
        Console.WriteLine(diffHtml);
    }
    return;
}

// ---- Snapshot / compare-save / compare-show (autostart only) --------------
if (parsed.Snapshot || parsed.CompareSave || parsed.CompareShow)
{
    if (!parsed.Quiet)
        AnsiConsole.MarkupLine("[grey]Scanning autostart locations...[/]");

    var scanned = AutostartScanner.ScanAll().Entries;
    foreach (var a in scanned)
    {
        var (score, level, reasons) = RiskScorer.ScoreAutostart(a);
        a.RiskScore = score;
        a.RiskLevel = level;
        a.RiskReasons = reasons;
    }

    if (parsed.CompareShow)
    {
        if (!File.Exists(baselinePath))
        {
            AnsiConsole.MarkupLine($"[red]No baseline found at {baselinePath}. Run with -CompareSave (or --compare-save) first.[/]");
            Environment.Exit(1);
        }

        var baseline = SnapshotComparer.Load(baselinePath);
        var current = new Snapshot
        {
            TakenUtc = DateTime.UtcNow,
            Entries = scanned.Select(e => new SnapshotEntry
            {
                Source = e.Source,
                Name = e.Name,
                Command = e.Command,
                KnownBenign = e.KnownBenign,
                RiskScore = e.RiskScore,
                RiskLevel = e.RiskLevel
            }).ToList()
        };
        var diff = SnapshotComparer.Diff(baseline, current);

        if (!parsed.Quiet)
        {
            AnsiConsole.MarkupLine("[bold cyan]Startup comparison (baseline vs current)[/]");
            AnsiConsole.MarkupLine($"[grey]baseline {baseline.TakenUtc:u}  ->  current {current.TakenUtc:u}[/]");
            AnsiConsole.WriteLine(SnapshotComparer.RenderConsole(diff));
        }

        string diffHtml = Path.Combine(logDir, $"compare_{stamp}.html");
        Directory.CreateDirectory(logDir);
        File.WriteAllText(diffHtml, SnapshotComparer.RenderHtml(diff));
        if (!parsed.Quiet)
        {
            AnsiConsole.MarkupLine($"\n[grey]Diff HTML:[/] [underline]{diffHtml}[/]");
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(diffHtml) { UseShellExecute = true }); }
            catch { }
        }
        else
        {
            Console.WriteLine(diffHtml);
        }
        return;
    }

    string outPath = parsed.CompareSave
        ? baselinePath
        : Path.Combine(logDir, $"snapshot_{stamp}.snapshot.json");
    Directory.CreateDirectory(logDir);
    File.WriteAllText(outPath, SnapshotComparer.TakeSnapshot(scanned));
    if (!parsed.Quiet)
        AnsiConsole.MarkupLine($"[green]Snapshot written:[/] {outPath}  ({scanned.Count} entries)");
    else
        Console.WriteLine(outPath);
    return;
}

// ---- Full report ----------------------------------------------------------

// ---- 1. Load and merge captured events -----------------------------------
var creates = new Dictionary<string, CaptureRecord>();
var terminates = new Dictionary<string, DateTime>();
int skippedRecords = 0;

string[] logFiles = Directory.Exists(logDir)
    ? Directory.GetFiles(logDir, "capture*.jsonl")
    : Array.Empty<string>();

foreach (var logFile in logFiles)
{
    if (!File.Exists(logFile)) continue;

    const int maxRetries = 3;
    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
        try
        {
            foreach (var line in File.ReadLines(logFile))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                CaptureRecord? rec;
                try { rec = JsonSerializer.Deserialize<CaptureRecord>(line); }
                catch { skippedRecords++; continue; }
                if (rec == null || string.IsNullOrEmpty(rec.ProcessGuid)) { skippedRecords++; continue; }

                if (rec.Kind == "create") creates[rec.ProcessGuid] = rec;
                else terminates[rec.ProcessGuid] = rec.TimeUtc;
            }
            break;
        }
        catch (IOException) when (attempt < maxRetries)
        {
            Thread.Sleep(200 * attempt);
        }
    }
}

var events = creates.Values
    .Select(c => new MergedEvent
    {
        Create = c,
        TerminatedUtc = terminates.TryGetValue(c.ProcessGuid, out var t) ? t : null
    })
    .OrderByDescending(e => e.Create.TimeUtc)
    .ToList();

if (parsed.Since.HasValue)
    events = events.Where(e => e.Create.TimeUtc >= parsed.Since.Value).ToList();

if (skippedRecords > 0 && !parsed.Quiet)
    AnsiConsole.MarkupLine($"[grey]Note: {skippedRecords} record(s) skipped due to parsing errors[/]\n");

if (events.Count == 0 && !parsed.Quiet)
    AnsiConsole.MarkupLine("[yellow]No captures yet.[/] Make sure InspectorService is running ([bold]Inspector.ps1 -Status[/]) and Sysmon is installed, then wait for the popup to happen again.\n");

if (parsed.FlashOnly)
{
    events = events.Where(e => e.IsFlashProcess).ToList();
    if (!parsed.Quiet)
        AnsiConsole.MarkupLine($"[grey]Flash filter: showing only {events.Count} process(es) with lifetime < {InspectorConstants.FlashProcessThresholdMs}ms[/]");
}

// ---- 2. Scan autostart locations ------------------------------------------
if (!parsed.Quiet)
    AnsiConsole.MarkupLine("[grey]Scanning autostart locations...[/]");
var autostart = AutostartScanner.ScanAll().Entries;

// ---- 3. Correlate + risk-flag each event -----------------------------------
foreach (var ev in events)
{
    var c = ev.Create;
    bool signedTrusted = !string.IsNullOrEmpty(c.SignedStatus) &&
        (c.SignedStatus.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
         c.IsSysInternalOrMicrosoftSigned ||
         c.Company?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) == true);

    var match = autostart.FirstOrDefault(a =>
        (!string.IsNullOrEmpty(c.ParentCommandLine) && a.Command.Contains(c.ParentCommandLine, StringComparison.OrdinalIgnoreCase)) ||
        (!string.IsNullOrEmpty(c.CommandLine) && a.Command.Length > 10 && c.CommandLine.Contains(a.Command, StringComparison.OrdinalIgnoreCase)));

    if (match != null)
        ev.LikelyTrigger = $"[{match.Source}] {match.Name}";

    var ancestorChain = new List<string>();
    var currentGuid = c.ParentProcessGuid;
    int depth = 0;
    while (!string.IsNullOrEmpty(currentGuid) && depth < 10)
    {
        if (creates.TryGetValue(currentGuid, out var parent))
        {
            ancestorChain.Add($"{Path.GetFileName(parent.Image)} ({parent.Pid})");
            currentGuid = parent.ParentProcessGuid;
        }
        else
        {
            break;
        }
        depth++;
    }
    ev.AncestorChain = ancestorChain;

    if (AutostartScanner.IsKnownBenign(c.CommandLine ?? "") || AutostartScanner.IsKnownBenign(c.ParentCommandLine ?? "") || signedTrusted)
        ev.RiskLevel = "benign";
    else if (match != null && !match.KnownBenign)
        ev.RiskLevel = "investigate";
    else
        ev.RiskLevel = "unknown";

    var (score, level, reasons) = RiskScorer.ScoreProcess(c);
    ev.RiskScore = score;
    ev.RiskLevelDetailed = level;
    ev.RiskReasons = reasons;
}

foreach (var a in autostart)
{
    var (score, level, reasons) = RiskScorer.ScoreAutostart(a);
    a.RiskScore = score;
    a.RiskLevel = level;
    a.RiskReasons = reasons;
}

// ---- 4. Exports -------------------------------------------------------------
Directory.CreateDirectory(logDir);

if (!string.IsNullOrEmpty(parsed.ExportFile))
{
    if (string.Equals(parsed.Format, "csv", StringComparison.OrdinalIgnoreCase))
        CsvExporter.Export(events, autostart, parsed.ExportFile);
    else
        JsonExporter.Export(events, autostart, parsed.ExportFile);
    if (!parsed.Quiet)
        AnsiConsole.MarkupLine($"[green]Data exported to:[/] [underline]{parsed.ExportFile}[/]\n");
    else
        Console.WriteLine(parsed.ExportFile);
    return;
}

if (parsed.JsonOut != null)
{
    JsonExporter.Export(events, autostart, parsed.JsonOut);
    if (!parsed.Quiet) AnsiConsole.MarkupLine($"[green]JSON export:[/] {parsed.JsonOut}");
}
if (parsed.CsvOut != null)
{
    CsvExporter.Export(events, autostart, parsed.CsvOut);
    if (!parsed.Quiet) AnsiConsole.MarkupLine($"[green]CSV export:[/] {parsed.CsvOut}");
}

// ---- 5. Console summary (quick check) --------------------------------------
if (parsed.Quiet)
{
    int flaggedQ = events.Count(e => e.RiskLevel == "investigate");
    Console.WriteLine($"captured={events.Count};investigate={flaggedQ};autostart={autostart.Count}");
    return;
}

int flaggedN = events.Count(e => e.RiskLevel == "investigate");
int benignN = events.Count(e => e.RiskLevel == "benign");
int unknownN = events.Count(e => e.RiskLevel == "unknown");

var summaryGrid = new Grid();
summaryGrid.AddColumn(); summaryGrid.AddColumn(); summaryGrid.AddColumn(); summaryGrid.AddColumn(); summaryGrid.AddColumn();
summaryGrid.AddRow(
    $"[bold]{events.Count}[/]\n[grey]captured[/]",
    flaggedN > 0 ? $"[bold red]{flaggedN}[/]\n[grey]investigate[/]" : $"[grey]{flaggedN}\ninvestigate[/]",
    $"[bold yellow]{unknownN}[/]\n[grey]unknown[/]",
    $"[bold green]{benignN}[/]\n[grey]benign[/]",
    $"[bold]{autostart.Count}[/]\n[grey]autostart entries[/]");
AnsiConsole.Write(new Panel(summaryGrid).Header("Summary").Border(BoxBorder.Rounded).Padding(1, 0));
AnsiConsole.WriteLine();

var table = new Table().Border(TableBorder.Rounded);
table.AddColumn("Risk");
table.AddColumn("Score");
table.AddColumn("Date & Time");
table.AddColumn("Process");
table.AddColumn("Lifetime");
table.AddColumn("Likely trigger");

int displayLimit = 25;
foreach (var ev in events.Take(displayLimit))
{
    string riskCell = ev.RiskLevel switch
    {
        "investigate" => "[red]INVESTIGATE[/]",
        "benign" => "[green]benign[/]",
        _ => "[yellow]unknown[/]"
    };
    string scoreCell = ev.RiskLevelDetailed switch
    {
        "high" => $"[red]{ev.RiskScore}[/]",
        "medium" => $"[yellow]{ev.RiskScore}[/]",
        _ => $"[green]{ev.RiskScore}[/]"
    };
    string lifetime = ev.LifetimeMs.HasValue ? $"{ev.LifetimeMs.Value:0} ms" : "-";
    string timestamp = ev.Create.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    table.AddRow(riskCell, scoreCell, timestamp,
        ev.Create.Image, lifetime, ev.LikelyTrigger ?? "(no autostart match found)");
}
AnsiConsole.Write(table);

if (events.Count > displayLimit)
    AnsiConsole.MarkupLine($"\n[grey]Showing {displayLimit} of {events.Count} events. See HTML report for all.[/]");

var flagged = events.Where(e => e.RiskLevel == "investigate").ToList();
if (flagged.Any())
    AnsiConsole.MarkupLine($"\n[red bold]{flagged.Count} item(s) flagged for investigation.[/] See the HTML report for full command lines, hashes, and signer info.");
else if (events.Count > 0)
    AnsiConsole.MarkupLine("\n[green]Nothing flagged  -  everything captured matches a known-benign pattern or a trusted publisher.[/]");

// ---- 6. HTML report (deep dive) --------------------------------------------
HtmlReportBuilder.Build(events, autostart, htmlOut);
AnsiConsole.MarkupLine($"\n[grey]Full HTML report:[/] [underline]{htmlOut}[/]");
CleanupOldReports(logDir, retentionDays: 30);

if (!parsed.NoOpen)
{
    try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(htmlOut) { UseShellExecute = true }); }
    catch { }
}

static void CleanupOldReports(string logDir, int retentionDays)
{
    try
    {
        if (!Directory.Exists(logDir)) return;

        var cutoffDate = DateTime.Now.AddDays(-retentionDays);
        int deletedCount = 0;

        foreach (var reportFile in Directory.GetFiles(logDir, "report_*.html"))
        {
            try
            {
                if (new FileInfo(reportFile).LastWriteTime < cutoffDate)
                {
                    File.Delete(reportFile);
                    deletedCount++;
                }
            }
            catch { }
        }

        if (deletedCount > 0)
            AnsiConsole.MarkupLine($"[grey]Cleaned up {deletedCount} old report(s) (older than {retentionDays} days)[/]");
    }
    catch { }
}

/// <summary>
/// CLI argument parser for InspectorReport.
/// </summary>
public class ArgsParser
{
    public string? ExportFile { get; }
    public string Format { get; } = "json";
    public DateTime? Since { get; }
    public bool NoOpen { get; }
    public bool FlashOnly { get; }
    public bool Quiet { get; }
    public string? JsonOut { get; }
    public string? CsvOut { get; }
    public bool Snapshot { get; }
    public bool CompareSave { get; }
    public bool CompareShow { get; }
    public string? CompareBefore { get; }
    public string? CompareAfter { get; }
    public string? CompareOut { get; }

    public ArgsParser(string[] args)
    {
        string? export = null, format = "json", since = null;
        string? json = null, csv = null;
        string? before = null, after = null, outPath = null;
        bool noOpen = false, flashOnly = false, quiet = false;
        bool snapshot = false, compareSave = false, compareShow = false;

        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg.ToLowerInvariant())
            {
                case "--export":
                case "-e":
                    if (i + 1 < args.Length) export = args[++i];
                    break;
                case "--format":
                case "-f":
                    if (i + 1 < args.Length) format = args[++i].ToLowerInvariant();
                    break;
                case "--since":
                    if (i + 1 < args.Length) since = args[++i];
                    break;
                case "--no-open":
                case "-n":
                    noOpen = true;
                    break;
                case "--flash-only":
                case "-flash":
                    flashOnly = true;
                    break;
                case "--quiet":
                    quiet = true;
                    break;
                case "--json":
                    if (i + 1 < args.Length) json = args[++i];
                    break;
                case "--csv":
                    if (i + 1 < args.Length) csv = args[++i];
                    break;
                case "--snapshot":
                    snapshot = true;
                    break;
                case "--compare-save":
                    compareSave = true;
                    break;
                case "--compare-show":
                    compareShow = true;
                    break;
                case "--compare":
                    for (int j = i + 1; j < args.Length; j++)
                    {
                        if (args[j].StartsWith("--")) break;
                        if (before == null) before = args[j];
                        else if (after == null) after = args[j];
                    }
                    break;
                case "--out":
                    if (i + 1 < args.Length) outPath = args[++i];
                    break;
            }
        }

        ExportFile = export;
        if (format != null) Format = format;
        if (since != null) Since = ParseSince(since);
        NoOpen = noOpen;
        FlashOnly = flashOnly;
        Quiet = quiet;
        JsonOut = json;
        CsvOut = csv;
        Snapshot = snapshot;
        CompareSave = compareSave;
        CompareShow = compareShow;
        CompareBefore = before;
        CompareAfter = after;
        CompareOut = outPath;
    }

    private static DateTime? ParseSince(string value)
    {
        if (DateTime.TryParse(value, out var result))
            return result;

        var match = System.Text.RegularExpressions.Regex.Match(value, @"^(\d+)([dh])$");
        if (match.Success)
        {
            var num = int.Parse(match.Groups[1].Value);
            var unit = match.Groups[2].Value;
            return unit switch
            {
                "h" => DateTime.Now.AddHours(-num),
                "d" => DateTime.Now.AddDays(-num),
                _ => null
            };
        }

        return null;
    }
}
