using Microsoft.Win32;
using System.Management;

namespace Inspector.Report;

public class AutostartEntry
{
    public string Source { get; set; } = "";      // e.g. "Scheduled Task", "Run Key", "WMI Subscription"
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public bool KnownBenign { get; set; }
    public string? FileHash { get; set; }         // SHA256 if available
}

public static class AutostartScanner
{
    // Cache for autostart entries with TTL
    private static List<AutostartEntry>? _cachedEntries;
    private static DateTime _cacheTime = DateTime.MinValue;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    public static bool IsKnownBenign(string text) =>
        Inspector.Common.InspectorConstants.KnownBenignPatterns.Any(p =>
            text.Contains(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Gets autostart entries, using cache if still valid
    /// </summary>
    public static List<AutostartEntry> ScanAll(bool forceRefresh = false)
    {
        if (!forceRefresh && _cachedEntries != null && DateTime.Now - _cacheTime < CacheDuration)
        {
            return _cachedEntries;
        }

        var entries = new List<AutostartEntry>();
        entries.AddRange(ScanRunKeys());
        entries.AddRange(ScanStartupFolders());
        entries.AddRange(ScanScheduledTasks());
        entries.AddRange(ScanWmiSubscriptions());
        entries.AddRange(ScanWinlogon());

        // Update cache
        _cachedEntries = entries;
        _cacheTime = DateTime.Now;

        return entries;
    }

    /// <summary>
    /// Force refresh the cache (useful after changes)
    /// </summary>
    public static void InvalidateCache() => _cacheTime = DateTime.MinValue;

    private static List<AutostartEntry> ScanRunKeys()
    {
        var results = new List<AutostartEntry>();
        var hives = new (RegistryKey hive, string path, string hiveName)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        };

        foreach (var (hive, path, hiveName) in hives)
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) continue;
            foreach (var name in key.GetValueNames())
            {
                var val = key.GetValue(name)?.ToString() ?? "";
                results.Add(new AutostartEntry
                {
                    Source = $"Run Key ({hiveName})",
                    Name = $"{path}\\{name}",
                    Command = val,
                    KnownBenign = IsKnownBenign(val) || IsKnownBenign(name),
                    FileHash = GetFileHashFromCommand(val)
                });
            }
        }
        return results;
    }

    private static List<AutostartEntry> ScanStartupFolders()
    {
        var results = new List<AutostartEntry>();
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };
        foreach (var folder in folders)
        {
            if (!Directory.Exists(folder)) continue;
            foreach (var file in Directory.GetFiles(folder))
            {
                results.Add(new AutostartEntry
                {
                    Source = "Startup Folder",
                    Name = Path.GetFileName(file),
                    Command = file,
                    KnownBenign = IsKnownBenign(file),
                    FileHash = ComputeFileHash(file)
                });
            }
        }
        return results;
    }

    /// <summary>
    /// Uses the native Task Scheduler COM object directly (Schedule.Service) so no
    /// extra NuGet package is required just to enumerate tasks.
    /// </summary>
    private static List<AutostartEntry> ScanScheduledTasks()
    {
        var results = new List<AutostartEntry>();
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            dynamic service = Activator.CreateInstance(type!)!;
            service.Connect();
            WalkTaskFolder(service.GetFolder("\\"), results);
        }
        catch
        {
            // Task Scheduler COM unavailable  -  skip silently, other sources still run.
        }
        return results;
    }

    private static void WalkTaskFolder(dynamic folder, List<AutostartEntry> results)
    {
        foreach (dynamic task in folder.GetTasks(1))
        {
            try
            {
                string xml = task.Xml;
                bool hasLogonTrigger = xml.Contains("<LogonTrigger>", StringComparison.OrdinalIgnoreCase);
                bool touchesShell = xml.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                                  || xml.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)
                                  || xml.Contains("wscript", StringComparison.OrdinalIgnoreCase)
                                  || xml.Contains("cscript", StringComparison.OrdinalIgnoreCase)
                                  || xml.Contains("mshta", StringComparison.OrdinalIgnoreCase);

                if (hasLogonTrigger && touchesShell)
                {
                    string path = (string)task.Path;
                    results.Add(new AutostartEntry
                    {
                        Source = "Scheduled Task",
                        Name = path,
                        Command = xml,
                        KnownBenign = IsKnownBenign(path),
                        FileHash = ExtractExeHashFromXml(xml)
                    });
                }
            }
            catch { /* skip tasks we can't read */ }
        }

        foreach (dynamic sub in folder.GetFolders(0))
        {
            WalkTaskFolder(sub, results);
        }
    }

    private static List<AutostartEntry> ScanWmiSubscriptions()
    {
        var results = new List<AutostartEntry>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\subscription", "SELECT * FROM CommandLineEventConsumer");
            foreach (ManagementObject obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString() ?? "(unnamed)";
                var cmd = obj["CommandLineTemplate"]?.ToString() ?? "";
                results.Add(new AutostartEntry
                {
                    Source = "WMI Event Subscription",
                    Name = name,
                    Command = cmd,
                    KnownBenign = IsKnownBenign(name) || IsKnownBenign(cmd),
                    FileHash = GetFileHashFromCommand(cmd)
                });
            }
        }
        catch { /* WMI namespace may not exist on some systems */ }
        return results;
    }

    private static List<AutostartEntry> ScanWinlogon()
    {
        var results = new List<AutostartEntry>();
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        if (key == null) return results;

        var shell = key.GetValue("Shell")?.ToString() ?? "";
        var userinit = key.GetValue("Userinit")?.ToString() ?? "";

        bool shellOk = shell.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
        bool userinitOk = userinit.TrimEnd(',').Equals(
            @"C:\Windows\system32\userinit.exe", StringComparison.OrdinalIgnoreCase);

        results.Add(new AutostartEntry { Source = "Winlogon", Name = "Shell", Command = shell, KnownBenign = shellOk });
        results.Add(new AutostartEntry { Source = "Winlogon", Name = "Userinit", Command = userinit, KnownBenign = userinitOk });
        return results;
    }

    #region Helper Methods

    private static string? GetFileHashFromCommand(string command)
    {
        if (string.IsNullOrEmpty(command)) return null;

        // Try to extract executable path from command
        var exePath = ExtractExePath(command);
        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
            return ComputeFileHash(exePath);
        }
        return null;
    }

    private static string? ExtractExePath(string command)
    {
        if (string.IsNullOrEmpty(command)) return null;

        // Remove common wrappers
        command = command.Trim();

        // Handle quoted paths
        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            if (end > 1) return command[1..end];
        }

        // Handle unquoted paths (take first token)
        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 0)
        {
            var path = parts[0];
            if (path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || path.Contains('\\'))
            {
                return path;
            }
        }

        return null;
    }

    private static string? ExtractExeHashFromXml(string xml)
    {
        // Try to find executable path in XML
        var match = System.Text.RegularExpressions.Regex.Match(
            xml, @"<Command>([^<]+)</Command>", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (match.Success)
        {
            return GetFileHashFromCommand(match.Groups[1].Value);
        }
        return null;
    }

    private static string? ComputeFileHash(string filePath)
    {
        try
        {
            if (!File.Exists(filePath)) return null;

            using var stream = File.OpenRead(filePath);
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    #endregion
}