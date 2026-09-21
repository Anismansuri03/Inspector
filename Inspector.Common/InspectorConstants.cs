namespace Inspector.Common;

/// <summary>
/// Centralized configuration and constants for Inspector.
/// Loaded from config.json with fallback to defaults.
/// </summary>
public static class InspectorConstants
{
    // Default paths
    public const string DefaultLogDirectory = @"C:\ProgramData\Inspector";
    public const string CaptureFileName = "capture.jsonl";
    public const string ConfigFileName = "config.json";

    // Default limits
    public const long DefaultMaxFileSizeBytes = 50 * 1024 * 1024; // 50 MB
    public const int DefaultRetentionDays = 30;

    // Process lifetime thresholds (milliseconds)
    public const int FlashProcessThresholdMs = 5000; // Anything under 5 seconds is "flash"

    // Size limits for input validation
    public const int MaxStringFieldLength = 10000;
    public const int MaxHashLength = 500;

    // Target images to monitor
    public static readonly string[] DefaultTargetImages =
    {
        "powershell.exe", "powershell_ise.exe", "pwsh.exe", "pwsh.dll",
        "cmd.exe", "conhost.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        // Common malware vectors
        "msiexec.exe", "regsvr32.exe", "rundll32.exe",
        "certutil.exe", "bitsadmin.exe"
    };

    // Known benign patterns for autostart
    public static readonly string[] KnownBenignPatterns =
    {
        "MicrosoftEdgeUpdateTaskMachine", "GoogleUpdateTaskMachine", "OneDrive Standalone Update",
        "Microsoft Compatibility Appraiser", "CreateExplorerShellUnelevatedTask",
        "Application Experience", "Adobe Acrobat Update Task", "WindowsUpdate",
        "NvTmMon", "NvTmRep", "\\HP\\", "\\Dell\\", "\\Lenovo\\", "Autochk",
        "Windows Defender", "WindowsSecurity", "SecurityHealth"
    };
}

/// <summary>
/// User configuration loaded from config.json
/// </summary>
public class InspectorConfig
{
    public string LogDirectory { get; set; } = InspectorConstants.DefaultLogDirectory;
    public List<string> TargetImages { get; set; } = InspectorConstants.DefaultTargetImages.ToList();
    public long MaxLogSizeMB { get; set; } = 50;
    public int RetentionDays { get; set; } = 30;
    public bool AutoStart { get; set; } = true;
    public bool EnableNetworkTracking { get; set; } = false;
    public bool EnableFileTracking { get; set; } = false;

    public string CaptureFilePath => Path.Combine(LogDirectory, InspectorConstants.CaptureFileName);
    public long MaxFileSizeBytes => MaxLogSizeMB * 1024 * 1024;

    /// <summary>
    /// Loads configuration from disk or returns defaults
    /// </summary>
    public static InspectorConfig Load(string? customPath = null)
    {
        var configPath = customPath ?? Path.Combine(
            InspectorConstants.DefaultLogDirectory,
            InspectorConstants.ConfigFileName);

        try
        {
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                var config = System.Text.Json.JsonSerializer.Deserialize<InspectorConfig>(json);
                if (config != null) return config;
            }
        }
        catch
        {
            // Return defaults on any error
        }

        return new InspectorConfig();
    }

    /// <summary>
    /// Saves current configuration to disk
    /// </summary>
    public void Save(string? customPath = null)
    {
        var configPath = customPath ?? Path.Combine(
            LogDirectory,
            InspectorConstants.ConfigFileName);

        var dir = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var json = System.Text.Json.JsonSerializer.Serialize(this, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true
        });
        File.WriteAllText(configPath, json);
    }
}