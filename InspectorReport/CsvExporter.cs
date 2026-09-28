using System.Text;
using Inspector.Common;

namespace Inspector.Report;

/// <summary>
/// Two-section CSV export: captured events first, then the autostart inventory,
/// each with its own header row. Opens directly in Excel/Sheets.
/// </summary>
public static class CsvExporter
{
    public static void Export(List<MergedEvent> events, List<AutostartEntry> autostart, string path)
    {
        var csv = new StringBuilder();

        csv.AppendLine("# Captured events");
        csv.AppendLine("TimestampUtc,Pid,Image,CommandLine,ParentImage,ParentCommandLine,User,Company,RiskLevel,RiskScore,RiskLevelDetailed,RiskReasons,LifetimeMs,LikelyTrigger,Hashes");
        foreach (var e in events)
        {
            var c = e.Create;
            csv.AppendLine(string.Join(",",
                Q(c.TimeUtc.ToString("yyyy-MM-dd HH:mm:ss")),
                c.Pid,
                Q(c.Image),
                Q(c.CommandLine),
                Q(c.ParentImage),
                Q(c.ParentCommandLine),
                Q(c.User),
                Q(c.Company),
                Q(e.RiskLevel),
                e.RiskScore,
                Q(e.RiskLevelDetailed),
                Q(string.Join("; ", e.RiskReasons)),
                e.LifetimeMs.HasValue ? e.LifetimeMs.Value.ToString("0") : "",
                Q(e.LikelyTrigger),
                Q(c.Hashes)));
        }

        csv.AppendLine();
        csv.AppendLine("# Autostart inventory");
        csv.AppendLine("Source,Name,Command,KnownBenign,RiskScore,RiskLevel,RiskReasons,FileHash,Publisher");
        foreach (var a in autostart)
        {
            csv.AppendLine(string.Join(",",
                Q(a.Source),
                Q(a.Name),
                Q(a.Command),
                a.KnownBenign ? "true" : "false",
                a.RiskScore,
                Q(a.RiskLevel),
                Q(string.Join("; ", a.RiskReasons)),
                Q(a.FileHash),
                Q(a.Publisher)));
        }

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, csv.ToString());
    }

    private static string Q(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return "\"" + s.Replace("\"", "\"\"").Replace("\n", " ").Replace("\r", "") + "\"";
    }
}
