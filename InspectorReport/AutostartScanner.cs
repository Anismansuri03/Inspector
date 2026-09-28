using Microsoft.Win32;
using System.Management;
using System.Security.Cryptography.X509Certificates;

namespace Inspector.Report;

/// <summary>
/// Represents a single autostart / persistence entry discovered on the system.
/// Each entry has a risk score (0-100) and a human-readable risk level
/// ("Likely benign" / "Investigate" / "Probably suspicious").
/// </summary>
public class AutostartEntry
{
    public string Source { get; set; } = "";      // e.g. "Scheduled Task", "Run Key", "WMI Subscription"
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public bool KnownBenign { get; set; }
    public string? FileHash { get; set; }         // SHA256 if available
    public int RiskScore { get; set; } = 0;       // 0-100, computed by heuristics
    public string RiskLevel { get; set; } = "unknown"; // "Likely benign", "Investigate", "Probably suspicious"
    public List<string> RiskFactors { get; set; } = new(); // Human-readable reasons
    public List<string> RiskReasons { get => RiskFactors; set => RiskFactors = value; }
    public bool IsFlashProcess { get; set; }      // Process with lifetime < threshold
    public string? Publisher { get; set; }        // Certificate subject if signed
    public bool IsMicrosoftSigned { get; set; }    // True if signed by Microsoft
    public DateTime? FileModified { get; set; }   // Last write time of the executable if found
}

/// <summary>
/// Results from a full autostart scan.
/// </summary>
public class AutostartScanResult
{
    public List<AutostartEntry> Entries { get; set; } = new();
    public List<ScanError> Errors { get; set; } = new();
    public int TotalScanned => Entries.Count;
    public int BenignCount => Entries.Count(e => e.RiskLevel == "Likely benign");
    public int InvestigateCount => Entries.Count(e => e.RiskLevel == "Investigate");
    public int SuspiciousCount => Entries.Count(e => e.RiskLevel == "Probably suspicious");
}

/// <summary>
/// Non-fatal errors encountered during scanning (e.g. permission denied on a key).
/// </summary>
public class ScanError
{
    public string Source { get; set; } = "";
    public string Message { get; set; } = "";
}

public static class AutostartScanner
{
    // Cache for autostart entries with TTL
    private static AutostartScanResult? _cachedResult;
    private static DateTime _cacheTime = DateTime.MinValue;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    // Set to track commands already seen to avoid duplicates across scanners
    private static readonly HashSet<string> _seenCommands = new(StringComparer.OrdinalIgnoreCase);

    public static bool IsKnownBenign(string text) =>
        Inspector.Common.InspectorConstants.KnownBenignPatterns.Any(p =>
            text.Contains(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Gets autostart entries, using cache if still valid.
    /// Returns a full scan result with entries, errors, and summary counts.
    /// </summary>
    public static AutostartScanResult ScanAll(bool forceRefresh = false, bool computeHash = true)
    {
        if (!forceRefresh && _cachedResult != null && DateTime.Now - _cacheTime < CacheDuration)
        {
            return _cachedResult;
        }

        _seenCommands.Clear();
        var result = new AutostartScanResult();

        try { result.Entries.AddRange(ScanRunKeys()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Run Keys", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanRunOnceKeys()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "RunOnce Keys", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanStartupFolders()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Startup Folders", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanScheduledTasks()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Scheduled Tasks", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanWmiSubscriptions()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "WMI Subscriptions", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanWinlogon()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Winlogon", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanWin32StartupCommand()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Win32_StartupCommand", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanServices(computeHash)); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "Services", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanAppInitDlls()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "AppInit_DLLs", Message = ex.Message }); }

        try { result.Entries.AddRange(ScanBootExecute()); }
        catch (Exception ex) { result.Errors.Add(new ScanError { Source = "BootExecute", Message = ex.Message }); }

        // Optional deep sources
        try { result.Entries.AddRange(ScanBrowserExtensions()); }
        catch { /* non-fatal — browser enumeration may fail silently */ }

        try { result.Entries.AddRange(ScanOfficeAddins()); }
        catch { /* non-fatal */ }

        // Compute risk scores for all entries
        foreach (var entry in result.Entries)
        {
            ComputeRiskScore(entry, computeHash);
        }

        // Update cache
        _cachedResult = result;
        _cacheTime = DateTime.Now;

        return result;
    }

    /// <summary>
    /// Force refresh the cache (useful after changes)
    /// </summary>
    public static void InvalidateCache() => _cacheTime = DateTime.MinValue;

    /// <summary>
    /// Gets a flat list of entries (backward compatibility with existing callers).
    /// </summary>
    public static List<AutostartEntry> ScanAllEntries(bool forceRefresh = false)
        => ScanAll(forceRefresh).Entries;

    #region Scanner Methods

    private static List<AutostartEntry> ScanRunKeys()
    {
        var results = new List<AutostartEntry>();
        var hives = new (RegistryKey hive, string path, string hiveName)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM-WOW64"),
        };

        foreach (var (hive, path, hiveName) in hives)
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) continue;
            foreach (var name in key.GetValueNames())
            {
                var val = key.GetValue(name)?.ToString() ?? "";
                if (val.Length > 0)
                    TryAddEntry(results, $"Run Key ({hiveName})", $"{path}\\{name}", val);
            }
        }
        return results;
    }

    private static List<AutostartEntry> ScanRunOnceKeys()
    {
        var results = new List<AutostartEntry>();
        var hives = new (RegistryKey hive, string path, string hiveName)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM-WOW64"),
        };

        foreach (var (hive, path, hiveName) in hives)
        {
            using var key = hive.OpenSubKey(path);
            if (key == null) continue;
            foreach (var name in key.GetValueNames())
            {
                var val = key.GetValue(name)?.ToString() ?? "";
                if (val.Length > 0)
                    TryAddEntry(results, $"RunOnce Key ({hiveName})", $"{path}\\{name}", val);
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
                TryAddEntry(results, "Startup Folder", Path.GetFileName(file), file, computeHash: false, isPath: true);
            }
        }
        return results;
    }

    /// <summary>
    /// Uses the native Task Scheduler COM object directly (Schedule.Service) so no
    /// extra NuGet package is required just to enumerate tasks.
    /// Captures tasks that have logon/startup triggers and touch shell interpreters.
    /// </summary>
    private static List<AutostartEntry> ScanScheduledTasks()
    {
        var results = new List<AutostartEntry>();
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type == null) return results;
            dynamic service = Activator.CreateInstance(type)!;
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
        try
        {
            foreach (dynamic task in folder.GetTasks(1))
            {
                try
                {
                    string xml = task.Xml;
                    // Check for triggers related to logon/startup/idle
                    bool hasLogonTrigger = xml.Contains("<LogonTrigger>", StringComparison.OrdinalIgnoreCase)
                                        || xml.Contains("<BootTrigger>", StringComparison.OrdinalIgnoreCase)
                                        || xml.Contains("<LogonTrigger>", StringComparison.OrdinalIgnoreCase);
                    bool touchesShell = xml.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("wscript", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("cscript", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("mshta", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("rundll32", StringComparison.OrdinalIgnoreCase)
                                      || xml.Contains("regsvr32", StringComparison.OrdinalIgnoreCase);

                    if (hasLogonTrigger && touchesShell)
                    {
                        string path = task.Path ?? "(unnamed)";
                        TryAddEntry(results, "Scheduled Task", path, xml, computeHash: false);
                    }
                }
                catch { /* skip tasks we can't read */ }
            }
        }
        catch { /* folder access denied - skip */ }

        try
        {
            foreach (dynamic sub in folder.GetFolders(0))
            {
                WalkTaskFolder(sub, results);
            }
        }
        catch { /* skip inaccessible subfolders */ }
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
                if (cmd.Length > 0)
                    TryAddEntry(results, "WMI Event Subscription", name, cmd);
            }
        }
        catch { /* WMI namespace may not exist on some systems */ }

        // Also check for __FilterToConsumerBinding + __EventFilter to catch event-based payloads
        try
        {
            using var searcher2 = new ManagementObjectSearcher(
                @"root\subscription", "SELECT * FROM ActiveScriptEventConsumer");
            foreach (ManagementObject obj in searcher2.Get())
            {
                var name = obj["Name"]?.ToString() ?? "(unnamed)";
                var cmd = obj["ScriptText"]?.ToString() ?? "";
                if (cmd.Length > 0)
                    TryAddEntry(results, "WMI Script Subscription", name, cmd);
            }
        }
        catch { /* WMI namespace may not exist */ }

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

        if (!string.IsNullOrEmpty(shell))
            TryAddEntry(results, "Winlogon", "Shell", shell, shellOk);
        if (!string.IsNullOrEmpty(userinit))
            TryAddEntry(results, "Winlogon", "Userinit", userinit, userinitOk);
        return results;
    }

    /// <summary>
    /// Queries Win32_StartupCommand via WMI. This catches shortcuts in various
    /// startup folders and command lines registered through the shell.
    /// Useful as a cross-check and catches entries the registry scanners might miss.
    /// </summary>
    private static List<AutostartEntry> ScanWin32StartupCommand()
    {
        var results = new List<AutostartEntry>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_StartupCommand");
            foreach (ManagementObject obj in searcher.Get())
            {
                var name = obj["Name"]?.ToString() ?? "(unnamed)";
                var cmd = obj["Command"]?.ToString() ?? "";
                var location = obj["Location"]?.ToString() ?? "";
                var user = obj["User"]?.ToString() ?? "";
                if (cmd.Length > 0)
                {
                    var displayName = $"{name} ({user})";
                    TryAddEntry(results, $"Win32_StartupCommand [{location}]", displayName, cmd);
                }
            }
        }
        catch { /* WMI not available */ }
        return results;
    }

    /// <summary>
    /// Enumerates Windows services with Automatic start type that launch
    /// script interpreters or shells. Malware commonly uses services for persistence.
    /// </summary>
    private static List<AutostartEntry> ScanServices(bool computeHash = true)
    {
        var results = new List<AutostartEntry>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, PathName, StartMode FROM Win32_Service");
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    var serviceName = obj["Name"]?.ToString() ?? "";
                    var startMode = obj["StartMode"]?.ToString() ?? "";
                    var path = obj["PathName"]?.ToString() ?? "";
                    var displayName = obj["DisplayName"]?.ToString() ?? serviceName;

                    if (startMode == "Auto" && !string.IsNullOrEmpty(path))
                    {
                        var pathLower = path.ToLowerInvariant();
                        bool touchesShell = pathLower.Contains("powershell")
                                         || pathLower.Contains("cmd.exe")
                                         || pathLower.Contains("wscript")
                                         || pathLower.Contains("cscript")
                                         || pathLower.Contains("mshta")
                                         || pathLower.Contains(".ps1")
                                         || pathLower.Contains(".vbs")
                                         || pathLower.Contains(".js")
                                         || pathLower.EndsWith(".bat")
                                         || pathLower.EndsWith(".cmd");

                        bool inTrustedPath = Inspector.Common.InspectorConstants.TrustedBasePaths
                            .Any(tp => path.StartsWith(tp, StringComparison.OrdinalIgnoreCase));

                        if (touchesShell || !inTrustedPath)
                        {
                            TryAddEntry(results, "Services", $"{displayName} ({serviceName})", path, computeHash);
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return results;
    }

    /// <summary>
    /// Checks AppInit_DLLs - DLLs injected into every user process.
    /// Location: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
    /// </summary>
    private static List<AutostartEntry> ScanAppInitDlls()
    {
        var results = new List<AutostartEntry>();
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
        if (key == null) return results;

        var appInitDlls = key.GetValue("AppInit_DLLs")?.ToString() ?? "";
        var loadAppInit = key.GetValue("LoadAppInit_DLLs")?.ToString() ?? "";

        if (!string.IsNullOrEmpty(appInitDlls) && loadAppInit != "0")
        {
            // Split comma-separated DLL list
            foreach (var dll in appInitDlls.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var dllPath = dll.Trim();
                if (!string.IsNullOrEmpty(dllPath))
                    TryAddEntry(results, "AppInit_DLLs", dllPath, dllPath, true);
            }
        }
        return results;
    }

    /// <summary>
    /// Checks BootExecute registry value (e.g., for malware that runs before the boot).
    /// Location: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
    /// </summary>
    private static List<AutostartEntry> ScanBootExecute()
    {
        var results = new List<AutostartEntry>();
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager");
        if (key == null) return results;

        var bootExecute = key.GetValue("BootExecute")?.ToString() ?? "";
        var expected = "autocheck autochk *";

        if (!string.IsNullOrEmpty(bootExecute))
        {
            var entry = TryAddEntry(results, "BootExecute", "BootExecute", bootExecute, true);
            // Mark as benign only if it's exactly the default
            if (entry != null && bootExecute.Equals(expected, StringComparison.OrdinalIgnoreCase))
                entry.KnownBenign = true;
        }
        return results;
    }

    /// <summary>
    /// Light enumeration of browser extension locations.
    /// Checks for extension manifest files on disk, flagging unsigned
    /// or temp-directory extensions.
    /// </summary>
    private static List<AutostartEntry> ScanBrowserExtensions()
    {
        var results = new List<AutostartEntry>();
        var extensionPaths = new[]
        {
            // Chrome / Edge
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google\\Chrome\\User Data\\Default\\Extensions"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\Edge\\User Data\\Default\\Extensions"),
            // Firefox
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles"),
        };

        foreach (var extPath in extensionPaths)
        {
            if (!Directory.Exists(extPath)) continue;
            try
            {
                // For Chrome/Edge: each subdirectory is an extension ID
                var dirs = Directory.GetDirectories(extPath);
                foreach (var dir in dirs)
                {
                    var extName = Path.GetFileName(dir);
                    // Just record the presence; this is a light inventory
                    TryAddEntry(results, "Browser Extension", extName, dir, true);
                }
            }
            catch { /* skip permission errors */ }
        }
        return results;
    }

    /// <summary>
    /// Checks Office add-in registrations (VSTO, COM add-ins).
    /// Location: HKCU\Software\Microsoft\Office\[version]\[app]\Resiliency\
    /// </summary>
    private static List<AutostartEntry> ScanOfficeAddins()
    {
        var results = new List<AutostartEntry>();
        var officeKeys = new[]
        {
            @"SOFTWARE\Microsoft\Office\16.0\Word\Resiliency\",
            @"SOFTWARE\Microsoft\Office\16.0\Excel\Resiliency\",
            @"SOFTWARE\Microsoft\Office\16.0\Outlook\Resiliency\",
        };

        foreach (var officeKey in officeKeys)
        {
            var fullPath = $@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{officeKey}";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey($@"Software\{officeKey}");
                if (key != null)
                {
                    var disabled = key.GetValue("CrashingAddinList")?.ToString() ?? "";
                    var disabledPs = key.GetValue("DisabledItems")?.ToString() ?? "";
                    // This is lightweight — just records we checked
                    if (!string.IsNullOrEmpty(disabled) || !string.IsNullOrEmpty(disabledPs))
                    {
                        TryAddEntry(results, "Office Add-in State", officeKey,
                            $"Disabled: {disabled} / CrashList: {disabledPs}", true);
                    }
                }
            }
            catch { /* skip */ }
        }
        return results;
    }

    #endregion

    #region Risk Scoring

    /// <summary>
    /// Computes a risk score (0-100) and human-readable factors for an autostart entry.
    /// Called after each entry is created, before it's added to the result list.
    /// </summary>
    private static void ComputeRiskScore(AutostartEntry entry, bool computeHash = true)
    {
        var factors = new List<string>();
        int score = 0;
        string cmd = entry.Command ?? "";
        string cmdLower = cmd.ToLowerInvariant();

        // --- Heuristic 1: Launches known dangerous interpreters ---
        string[] dangerousShells = {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
            "wmic.exe", "powershell_ise.exe"
        };
        foreach (var shell in dangerousShells)
        {
            if (cmdLower.Contains(shell))
            {
                factors.Add($"Launches {shell}");
                score += 15;
                break;
            }
        }

        // --- Heuristic 2: Suspicious paths (temp, appdata, ProgramData) ---
        string[] suspiciousPaths = {
            "\\temp\\", "\\appdata\\local\\temp\\", "\\programdata\\",
            "\\users\\public\\", "c:\\windows\\temp\\", "\\downloads\\",
            "\\appdata\\roaming\\", "\\local\\temp\\"
        };
        foreach (var path in suspiciousPaths)
        {
            if (cmdLower.Contains(path))
            {
                factors.Add($"Executes from suspicious path ({path})");
                score += 20;
                break;
            }
        }

        // --- Heuristic 3: Obfuscated commands ---
        if (cmdLower.Contains("-enc") || cmdLower.Contains("-encodedcommand") || cmdLower.Contains("-e "))
        {
            factors.Add("Uses PowerShell -EncodedCommand (obfuscation)");
            score += 25;
        }
        // Detect base64 blobs (long sequences of base64 characters)
        if (System.Text.RegularExpressions.Regex.IsMatch(cmd, @"[A-Za-z0-9+/]{50,}={0,2}"))
        {
            factors.Add("Contains long base64-encoded string (potential obfuscation)");
            score += 15;
        }
        if (cmdLower.Contains("iex") || cmdLower.Contains("invoke-expression"))
        {
            factors.Add("Uses Invoke-Expression (IEX)");
            score += 30;
        }
        if (cmdLower.Contains("downloadstring") || cmdLower.Contains("downloadfile") || cmdLower.Contains("webclient"))
        {
            factors.Add("Downloads content at runtime (DownloadString/WebClient)");
            score += 25;
        }

        // --- Heuristic 4: Hidden / bypass flags ---
        if (cmdLower.Contains("bypass") || cmdLower.Contains("-windowstyle hidden") ||
            cmdLower.Contains("-windowhidden") || cmdLower.Contains("-nop") || cmdLower.Contains("-noexit"))
        {
            factors.Add("Uses bypass or hidden window flags");
            score += 20;
        }
        if (cmdLower.Contains("registry::") || cmdLower.Contains("hkcu:\\") || cmdLower.Contains("hklm:\\"))
        {
            factors.Add("Manipulates registry from command line");
            score += 15;
        }
        if (cmdLower.Contains("[reflection") || cmdLower.Contains("system.text.encoding"))
        {
            factors.Add("Uses .NET reflection (potential in-memory loading)");
            score += 25;
        }

        // --- Heuristic 5: Missing publisher info ---
        if (computeHash && entry.FileHash == null && entry.Publisher == null &&
            !cmdLower.Contains("microsoft") && !entry.KnownBenign)
        {
            factors.Add("No file hash or publisher info available (unsigned or unknown)");
            score += 10;
        }

        // --- Heuristic 6: Recently created/modified files ---
        var exePath = ExtractExePath(cmd);
        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
            try
            {
                var fileInfo = new FileInfo(exePath);
                entry.FileModified = fileInfo.LastWriteTime;
                var age = DateTime.Now - fileInfo.LastWriteTime;
                if (age.TotalDays < Inspector.Common.InspectorConstants.RecentFileThresholdDays)
                {
                    factors.Add($"Binary recently modified ({age.Days} days ago)");
                    score += 15;
                }
                // Also check creation time
                age = DateTime.Now - fileInfo.CreationTime;
                if (age.TotalDays < Inspector.Common.InspectorConstants.RecentFileThresholdDays)
                {
                    factors.Add($"Binary recently created ({age.Days} days ago)");
                    score += 15;
                }
            }
            catch { /* non-fatal */ }
        }

        // --- Heuristic 7: Unknown vs known benign source ---
        if (entry.KnownBenign)
        {
            score = Math.Max(0, score - 15);  // reduce score for known benign
            if (score < 20)
            {
                factors.Add("Known benign pattern matched");
            }
        }

        // --- Heuristic 8: Non-standard location ---
        if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
        {
            bool inTrustedPath = Inspector.Common.InspectorConstants.TrustedBasePaths
                .Any(tp => exePath.StartsWith(tp, StringComparison.OrdinalIgnoreCase));
            if (!inTrustedPath && !entry.KnownBenign)
            {
                factors.Add($"Executable not in standard Program Files or System32");
                score += 10;
            }
        }

        // --- Determine risk level ---
        string riskLevel;
        if (entry.KnownBenign && score < 20)
            riskLevel = "Likely benign";
        else if (score >= 40)
            riskLevel = "Probably suspicious";
        else if (score >= 15)
            riskLevel = "Investigate";
        else
            riskLevel = "Investigate";  // Low-confidence baseline noise

        // Clamp score to 0-100
        entry.RiskScore = Math.Clamp(score, 0, 100);
        entry.RiskLevel = riskLevel;
        entry.RiskFactors = factors;
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Tries to add an entry to the results list, de-duplicating by command.
    /// Returns the entry if added, null if it was a duplicate.
    /// </summary>
    private static AutostartEntry? TryAddEntry(
        List<AutostartEntry> results,
        string source,
        string name,
        string command,
        bool computeHash = true,
        bool isPath = false,
        bool knownBenign = false)
    {
        if (string.IsNullOrEmpty(command)) return null;

        // Deduplicate by command hash
        if (!_seenCommands.Add(command))
        {
            return null; // Already seen
        }

        var entry = new AutostartEntry
        {
            Source = source,
            Name = name,
            Command = command,
            KnownBenign = knownBenign ? true : IsKnownBenign(command) || IsKnownBenign(name),
        };

        if (computeHash)
        {
            var exePath = ExtractExePath(command);
            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                entry.FileHash = ComputeFileHash(exePath);
                entry.Publisher = GetPublisherInfo(exePath, out bool isMicrosoftSigned);
                entry.IsMicrosoftSigned = isMicrosoftSigned;
            }
        }

        results.Add(entry);
        return entry;
    }

    private static string? GetFileHashFromCommand(string command)
    {
        if (string.IsNullOrEmpty(command)) return null;
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
        try
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                xml, @"<Command>([^<]+)</Command>", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return GetFileHashFromCommand(match.Groups[1].Value);
            }
        }
        catch { }
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

    /// <summary>
    /// Checks the digital signature of a file and returns the publisher name.
    /// Sets isMicrosoftSigned flag if the signer is Microsoft.
    /// </summary>
    private static string? GetPublisherInfo(string filePath, out bool isMicrosoftSigned)
    {
        isMicrosoftSigned = false;
        try
        {
            if (!File.Exists(filePath)) return null;

            var cert = X509Certificate.CreateFromSignedFile(filePath);
            if (cert == null) return "Unsigned";

            var cert2 = new X509Certificate2(cert);
            var cn = cert2.SubjectName.Format(false);

            // Check if Microsoft
            var subjectUpper = cn?.ToUpperInvariant() ?? "";
            isMicrosoftSigned = subjectUpper.Contains("MICROSOFT");

            return string.IsNullOrEmpty(cn) ? cert.Subject : cn;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return "Unsigned or invalid signature";
        }
        catch
        {
            return null;
        }
    }

    #endregion
}