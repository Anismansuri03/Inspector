using System.Text.Json;
using System.Text.Encodings.Web;
using Inspector.Common;

namespace Inspector.Report;

/// <summary>
/// Structured JSON export of captured events plus the scored autostart inventory.
/// Stable shape for tooling and issue attachments.
/// </summary>
public static class JsonExporter
{
    private static readonly JsonSerializerOptions Indented = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static void Export(List<MergedEvent> events, List<AutostartEntry> autostart, string path)
    {
        var payload = new
        {
            generatedUtc = DateTime.UtcNow,
            machine = Environment.MachineName,
            os = Environment.OSVersion.VersionString,
            user = Environment.UserDomainName + "\\" + Environment.UserName,
            counts = new
            {
                captured = events.Count,
                investigate = events.Count(e => e.RiskLevel == "investigate"),
                benign = events.Count(e => e.RiskLevel == "benign"),
                unknown = events.Count(e => e.RiskLevel == "unknown"),
                autostart = autostart.Count
            },
            events = events.Select(e =>
            {
                var c = e.Create;
                return new
                {
                    timestampUtc = c.TimeUtc,
                    terminatedUtc = e.TerminatedUtc,
                    lifetimeMs = e.LifetimeMs,
                    pid = c.Pid,
                    image = c.Image,
                    commandLine = c.CommandLine,
                    parentImage = c.ParentImage,
                    parentCommandLine = c.ParentCommandLine,
                    user = c.User,
                    integrityLevel = c.IntegrityLevel,
                    company = c.Company,
                    signedStatus = c.SignedStatus,
                    hashes = c.Hashes,
                    riskLevel = e.RiskLevel,
                    riskScore = e.RiskScore,
                    riskLevelDetailed = e.RiskLevelDetailed,
                    riskReasons = e.RiskReasons,
                    likelyTrigger = e.LikelyTrigger,
                    isFlashProcess = e.IsFlashProcess
                };
            }),
            autostart = autostart.Select(a => new
            {
                source = a.Source,
                name = a.Name,
                command = a.Command,
                knownBenign = a.KnownBenign,
                fileHash = a.FileHash,
                publisher = a.Publisher,
                riskScore = a.RiskScore,
                riskLevel = a.RiskLevel,
                riskReasons = a.RiskReasons
            })
        };

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(payload, Indented));
    }
}
