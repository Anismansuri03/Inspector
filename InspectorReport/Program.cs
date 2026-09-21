using System.Text.Json;
using Inspector.Common;
using Inspector.Report;
using Spectre.Console;

// Parse command line arguments
var argsObj = new ArgsParser(args);
var config = InspectorConfig.Load();

string logDir = config.LogDirectory;
string captureFile = config.CaptureFilePath;
string htmlOut = Path.Combine(logDir, $"report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
string? exportFile = argsObj.ExportFile;
DateTime? sinceFilter = argsObj.Since;

bool openHtml = !argsObj.NoOpen && string.IsNullOrEmpty(exportFile);

AnsiConsole.Write(new Rule("[bold cyan]Inspector Report[/]").LeftJustified());
AnsiConsole.MarkupLine($"[grey]{DateTime.Now:f}[/]\n");

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
            break; // success, exit retry loop
        }
        catch (IOException) when (attempt < maxRetries)
        {
            Thread.Sleep(200 * attempt); // back off: 200ms, 400ms, 600ms
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

// Apply time filter if specified
if (sinceFilter.HasValue)
{
    events = events.Where(e => e.Create.TimeUtc >= sinceFilter.Value).ToList();
}

// Report skipped records
if (skippedRecords > 0)
{
    AnsiConsole.MarkupLine($"[grey]Note: {skippedRecords} record(s) skipped due to parsing errors[/]\n");
}

if (events.Count == 0)
{
    AnsiConsole.MarkupLine("[yellow]No captures yet.[/] Make sure InspectorService is running ([bold]Inspector.ps1 -Status[/]) and Sysmon is installed, then wait for the popup to happen again.\n");
}

// ---- 2. Scan autostart locations ------------------------------------------
AnsiConsole.MarkupLine("[grey]Scanning autostart locations...[/]");
var autostart = AutostartScanner.ScanAll();

// ---- 3. Correlate + risk-flag each event -----------------------------------
foreach (var ev in events)
{
    var c = ev.Create;
    bool signedTrusted = !string.IsNullOrEmpty(c.Company) &&
        (c.Company.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));

    // Try to find an autostart entry whose command references this process's parent or command line
    var match = autostart.FirstOrDefault(a =>
        (!string.IsNullOrEmpty(c.ParentCommandLine) && a.Command.Contains(c.ParentCommandLine, StringComparison.OrdinalIgnoreCase)) ||
        (!string.IsNullOrEmpty(c.CommandLine) && a.Command.Length > 10 && c.CommandLine.Contains(a.Command, StringComparison.OrdinalIgnoreCase)));

    if (match != null)
        ev.LikelyTrigger = $"[{match.Source}] {match.Name}";

    if (AutostartScanner.IsKnownBenign(c.CommandLine ?? "") || AutostartScanner.IsKnownBenign(c.ParentCommandLine ?? "") || signedTrusted)
        ev.RiskLevel = "benign";
    else if (match != null && !match.KnownBenign)
        ev.RiskLevel = "investigate";
    else
        ev.RiskLevel = "unknown";
}

// ---- Export to file if requested -----------------------------------------
if (!string.IsNullOrEmpty(exportFile))
{
    ExportData(events, exportFile, argsObj.Format);
    AnsiConsole.MarkupLine($"[green]Data exported to:[/] [underline]{exportFile}[/]\n");
    return; // Skip console + HTML output
}

// ---- 4. Console summary (quick check) --------------------------------------
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
    string lifetime = ev.LifetimeMs.HasValue ? $"{ev.LifetimeMs.Value:0} ms" : "-";
    string timestamp = ev.Create.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    table.AddRow(riskCell, timestamp,
        ev.Create.Image, lifetime, ev.LikelyTrigger ?? "(no autostart match found)");
}
AnsiConsole.Write(table);

if (events.Count > displayLimit)
{
    AnsiConsole.MarkupLine($"\n[grey]Showing {displayLimit} of {events.Count} events. See HTML report for all.[/]");
}

var flagged = events.Where(e => e.RiskLevel == "investigate").ToList();
if (flagged.Any())
{
    AnsiConsole.MarkupLine($"\n[red bold]{flagged.Count} item(s) flagged for investigation.[/] See the HTML report for full command lines, hashes, and signer info.");
}
else if (events.Count > 0)
{
    AnsiConsole.MarkupLine("\n[green]Nothing flagged  -  everything captured matches a known-benign pattern or a trusted publisher.[/]");
}

// ---- 5. HTML report (deep dive) --------------------------------------------
Directory.CreateDirectory(logDir);
HtmlReportBuilder.Build(events, autostart, htmlOut);
AnsiConsole.MarkupLine($"\n[grey]Full HTML report:[/] [underline]{htmlOut}[/]");

// Clean up old HTML reports (older than 30 days)
CleanupOldReports(logDir, retentionDays: 30);

if (openHtml)
{
    try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(htmlOut) { UseShellExecute = true }); }
    catch { /* non-fatal if it can't auto-open */ }
}

// ---- Helper Functions ------------------------------------------------------

static void ExportData(List<MergedEvent> events, string filePath, string format)
{
    Directory.CreateDirectory(Path.GetDirectoryName(filePath) ?? ".");

    switch (format.ToLowerInvariant())
    {
        case "csv":
            var csv = new System.Text.StringBuilder();
            csv.AppendLine("Timestamp,Process,PID,CommandLine,User,RiskLevel,LifetimeMs,LikelyTrigger");
            foreach (var e in events)
            {
                var c = e.Create;
                csv.AppendLine($"\"{c.TimeUtc:yyyy-MM-dd HH:mm:ss}\",\"{c.Image}\",{c.Pid},\"{EscapeCsv(c.CommandLine)}\",\"{c.User}\",\"{e.RiskLevel}\",\"{e.LifetimeMs?.ToString("0") ?? ""}\",\"{EscapeCsv(e.LikelyTrigger)}\"");
            }
            File.WriteAllText(filePath, csv.ToString());
            break;

        case "json":
        default:
            var json = JsonSerializer.Serialize(events, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(filePath, json);
            break;
    }
}

static string EscapeCsv(string? s)
{
    if (string.IsNullOrEmpty(s)) return "";
    return s.Replace("\"", "\"\"").Replace("\n", " ").Replace("\r", "");
}

static void CleanupOldReports(string logDir, int retentionDays)
{
    try
    {
        if (!Directory.Exists(logDir)) return;

        var cutoffDate = DateTime.Now.AddDays(-retentionDays);
        var reportFiles = Directory.GetFiles(logDir, "report_*.html");
        int deletedCount = 0;

        foreach (var reportFile in reportFiles)
        {
            try
            {
                var fileInfo = new FileInfo(reportFile);
                if (fileInfo.LastWriteTime < cutoffDate)
                {
                    File.Delete(reportFile);
                    deletedCount++;
                }
            }
            catch
            {
                // Ignore individual file errors (might be locked, etc.)
            }
        }

        if (deletedCount > 0)
        {
            AnsiConsole.MarkupLine($"[grey]Cleaned up {deletedCount} old report(s) (older than {retentionDays} days)[/]");
        }
    }
    catch
    {
        // Non-fatal, just skip cleanup if something goes wrong
    }
}

// ---- Helper Classes --------------------------------------------------------

/// <summary>
/// Simple CLI argument parser for InspectorReport
/// </summary>
public class ArgsParser
{
    public string? ExportFile { get; }
    public string Format { get; } = "json";
    public DateTime? Since { get; }
    public bool NoOpen { get; }

    public ArgsParser(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i].ToLowerInvariant();
            switch (arg)
            {
                case "--export":
                case "-e":
                    if (i + 1 < args.Length) ExportFile = args[++i];
                    break;
                case "--format":
                case "-f":
                    if (i + 1 < args.Length) Format = args[++i].ToLowerInvariant();
                    break;
                case "--since":
                    if (i + 1 < args.Length) Since = ParseSince(args[++i]);
                    break;
                case "--no-open":
                case "-n":
                    NoOpen = true;
                    break;
            }
        }
    }

    private static DateTime? ParseSince(string value)
    {
        // Try parsing as ISO date
        if (DateTime.TryParse(value, out var result))
            return result;

        // Try parsing duration like "24h", "7d"
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