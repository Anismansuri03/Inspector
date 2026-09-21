namespace Inspector.Common;

/// <summary>
/// One captured process, built from Sysmon Event ID 1 (ProcessCreate) and later
/// enriched with Event ID 5 (ProcessTerminate) once the process exits.
/// Written as a single line of JSON per event to capture.jsonl; InspectorReport
/// folds the "create" and "terminate" lines for the same ProcessGuid together.
/// </summary>
public record CaptureRecord
{
    public string Kind { get; init; } = "create"; // "create" or "terminate"
    public DateTime TimeUtc { get; init; }
    public string ProcessGuid { get; init; } = "";
    public int Pid { get; init; }
    public string Image { get; init; } = "";
    public string? CommandLine { get; init; }
    public string? CurrentDirectory { get; init; }
    public string? User { get; init; }
    public string? IntegrityLevel { get; init; }
    public string? Company { get; init; }
    public string? Product { get; init; }
    public string? OriginalFileName { get; init; }
    public string? FileVersion { get; init; }
    public string? Description { get; init; }
    public string? Hashes { get; init; }
    public string? ParentProcessGuid { get; init; }
    public int? ParentPid { get; init; }
    public string? ParentImage { get; init; }
    public string? ParentCommandLine { get; init; }
    public string? ParentUser { get; init; }
    public string? LogonId { get; init; }
    public string? TerminalSessionId { get; init; }
}

/// <summary>
/// A "create" record merged with its matching "terminate" record (if one arrived),
/// so we know exactly how long the process lived - the key fact for a flash-and-vanish popup.
/// </summary>
public class MergedEvent
{
    public CaptureRecord Create { get; set; } = new();
    public DateTime? TerminatedUtc { get; set; }
    public double? LifetimeMs =>
        TerminatedUtc.HasValue ? (TerminatedUtc.Value - Create.TimeUtc).TotalMilliseconds : null;

    // Filled in by the autostart correlator
    public string? LikelyTrigger { get; set; }
    public string RiskLevel { get; set; } = "unknown"; // "benign", "unknown", "investigate"

    // Extended properties for enhanced reporting
    public string? FileHash { get; set; }
    public List<string> AncestorChain { get; set; } = new();
    public bool IsFlashProcess => LifetimeMs.HasValue && LifetimeMs.Value < InspectorConstants.FlashProcessThresholdMs;
}