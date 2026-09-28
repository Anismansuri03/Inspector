using Inspector.Common;

namespace Inspector.Report;

/// <summary>
/// Heuristic 0-100 risk scorer for captured processes and autostart entries.
/// Buckets: low (0-29), medium (30-59), high (60-100). Every contributing
/// reason is returned so the report can explain why something was flagged.
/// </summary>
public static class RiskScorer
{
    public static readonly string[] HighRiskCommandTokens =
    {
        "-EncodedCommand", " -enc ", " -e ", "IEX", "Invoke-Expression",
        "DownloadString", "DownloadFile", "Invoke-WebRequest", "Invoke-RestMethod",
        "WebClient", "Net.WebClient", "FromBase64String", "-nop ", "-w hidden",
        "Hidden", "Bypass", "-ExecutionPolicy Bypass", "Reflection.Assembly",
        "Start-Process", "bitsadmin", "certutil -urlcache"
    };

    public static readonly string[] SuspiciousPathPatterns =
    {
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
        "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\", "recycle.bin"
    };

    public static readonly string[] TrustedPublishers =
        { "Microsoft", "Google", "Mozilla", "Adobe" };

    public static readonly string[] ShellHosts =
        { "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta" };

    public static (int Score, string Level, List<string> Reasons) ScoreProcess(CaptureRecord c)
    {
        var reasons = new List<string>();
        int score = 0;
        string cmd = c.CommandLine ?? "";
        string image = c.Image ?? "";
        string parentImage = c.ParentImage ?? "";

        foreach (var token in HighRiskCommandTokens)
        {
            if (cmd.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"Indicator: {token.Trim()}");
                score += 25;
            }
        }

        if (HasLongBase64Run(cmd))
        {
            reasons.Add("Long base64-encoded blob (potential obfuscation)");
            score += 25;
        }

        if (IsShellHost(image))
        {
            reasons.Add("Launches a shell/script host");
            score += 15;
        }

        string cmdLower = cmd.ToLowerInvariant();
        foreach (var pattern in SuspiciousPathPatterns)
        {
            if (cmdLower.Contains(pattern))
            {
                reasons.Add($"Suspicious path ({pattern})");
                score += 30;
                break;
            }
        }

        string? dir = null;
        try { dir = string.IsNullOrEmpty(image) ? null : Path.GetDirectoryName(image); }
        catch { }

        if (!string.IsNullOrEmpty(dir))
        {
            bool trusted = InspectorConstants.TrustedBasePaths
                .Any(tp => dir.StartsWith(tp, StringComparison.OrdinalIgnoreCase));
            if (!trusted)
            {
                reasons.Add("Executable not in a standard trusted folder");
                score += 15;
            }
        }

        string company = c.Company ?? "";
        if (string.IsNullOrEmpty(company))
        {
            reasons.Add("No publisher/company info recorded");
            score += 20;
        }
        else if (!TrustedPublishers.Any(p => company.Contains(p, StringComparison.OrdinalIgnoreCase)))
        {
            reasons.Add($"Unrecognized publisher ({company})");
            score += 5;
        }

        if (!string.IsNullOrEmpty(image) && File.Exists(image))
        {
            try
            {
                var created = File.GetCreationTime(image);
                var age = DateTime.Now - created;
                if (age.TotalDays < 7)
                {
                    reasons.Add($"Binary created {age.Days} day(s) ago");
                    score += 25;
                }
                else if (age.TotalDays < 30)
                {
                    reasons.Add($"Binary created {age.Days} days ago");
                    score += 10;
                }
            }
            catch { }
        }

        if (IsShellHost(image) && IsShellHost(parentImage))
        {
            reasons.Add("Shell launched by another shell");
            score += 10;
        }

        score = Math.Clamp(score, 0, 100);
        if (reasons.Count == 0) reasons.Add("No risk indicators matched");
        return (score, Bucket(score), reasons);
    }

    public static (int Score, string Level, List<string> Reasons) ScoreAutostart(AutostartEntry entry)
    {
        var reasons = entry.RiskFactors.Count > 0
            ? new List<string>(entry.RiskFactors)
            : new List<string> { "No risk indicators matched" };
        int score = Math.Clamp(entry.RiskScore, 0, 100);
        return (score, Bucket(score), reasons);
    }

    public static string Bucket(int score) =>
        score >= 60 ? "high" : score >= 30 ? "medium" : "low";

    public static bool HasLongBase64Run(string? text, int minLength = 80)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return System.Text.RegularExpressions.Regex.IsMatch(
            text, $@"[A-Za-z0-9+/]{{{minLength},}}={{0,2}}");
    }

    private static bool IsShellHost(string imagePath)
    {
        if (string.IsNullOrEmpty(imagePath)) return false;
        string name = Path.GetFileName(imagePath).ToLowerInvariant();
        return ShellHosts.Any(h => name.StartsWith(h));
    }
}
