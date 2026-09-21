using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using System.Xml.Linq;
using System.Security.Cryptography.X509Certificates;
using Inspector.Common;

namespace Inspector.Service;

/// <summary>
/// Watches the Sysmon "Microsoft-Windows-Sysmon/Operational" event channel in real time
/// (push-based via EventLogWatcher - not polling, so it cannot miss a short-lived process)
/// and logs any create/terminate event for processes we care about.
/// </summary>
public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly InspectorConfig _config;

    // State for health monitoring
    private DateTime _lastEventTime = DateTime.MinValue;
    private int _totalCaptures = 0;
    private readonly object _stateLock = new();

    private EventLogWatcher? _watcher;

    public Worker(ILogger<Worker> logger, InspectorConfig config)
    {
        _logger = logger;
        _config = config;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(_config.LogDirectory);

        try
        {
            // XPath filter: only Sysmon Event ID 1 (ProcessCreate) or 5 (ProcessTerminate).
            // Filtering here (not in our own code) means Windows does the filtering at the
            // source, so we don't even receive events we don't care about.
            var query = new EventLogQuery(
                "Microsoft-Windows-Sysmon/Operational",
                PathType.LogName,
                "*[System[(EventID=1 or EventID=5)]]");

            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;

            _logger.LogInformation("InspectorService started, watching Sysmon in real time. Log: {LogDir}", _config.LogDirectory);

            // Start health monitoring task
            _ = MonitorHealthAsync(stoppingToken);

            // Keep running
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to attach to the Sysmon event log. Is Sysmon installed and running?");
        }
    }

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord == null) return;

        try
        {
            var xml = XDocument.Parse(e.EventRecord.ToXml());
            var ns = xml.Root!.GetDefaultNamespace();
            var eventId = e.EventRecord.Id;

            var data = xml.Descendants(ns + "Data")
                .ToDictionary(
                    d => d.Attribute("Name")?.Value ?? "",
                    d => TruncateString(d.Value, InspectorConstants.MaxStringFieldLength));

            string image = data.GetValueOrDefault("Image", "");
            if (!IsTargetProcess(image))
                return; // not a process we're watching

            var record = new CaptureRecord
            {
                Kind = eventId == 1 ? "create" : "terminate",
                TimeUtc = DateTime.TryParse(data.GetValueOrDefault("UtcTime"), out var t) ? t : DateTime.UtcNow,
                ProcessGuid = TruncateString(data.GetValueOrDefault("ProcessGuid", ""), 100),
                Pid = int.TryParse(data.GetValueOrDefault("ProcessId"), out var pid) ? pid : 0,
                Image = image,
                CommandLine = data.GetValueOrDefault("CommandLine"),
                CurrentDirectory = data.GetValueOrDefault("CurrentDirectory"),
                User = data.GetValueOrDefault("User"),
                IntegrityLevel = data.GetValueOrDefault("IntegrityLevel"),
                Company = data.GetValueOrDefault("Company"),
                Product = data.GetValueOrDefault("Product"),
                OriginalFileName = data.GetValueOrDefault("OriginalFileName"),
                FileVersion = data.GetValueOrDefault("FileVersion"),
                Description = data.GetValueOrDefault("Description"),
                Hashes = TruncateString(data.GetValueOrDefault("Hashes", ""), InspectorConstants.MaxHashLength),
                ParentProcessGuid = TruncateString(data.GetValueOrDefault("ParentProcessGuid", ""), 100),
                ParentPid = int.TryParse(data.GetValueOrDefault("ParentProcessId"), out var ppid) ? ppid : null,
                ParentImage = data.GetValueOrDefault("ParentImage"),
                ParentCommandLine = data.GetValueOrDefault("ParentCommandLine"),
                ParentUser = data.GetValueOrDefault("ParentUser"),
                LogonId = data.GetValueOrDefault("LogonId"),
                TerminalSessionId = data.GetValueOrDefault("TerminalSessionId"),
                // Publisher verification (may be slow, but only on create events)
                SignedStatus = eventId == 1 ? GetFileSignatureStatus(image) : null,
                IsSysInternalOrMicrosoftSigned = eventId == 1 ? CheckMicrosoftOrSysinternalsSignature(image) : false,
            };

            WriteCaptureRecord(record);

            // Update health state
            lock (_stateLock)
            {
                _lastEventTime = DateTime.UtcNow;
                _totalCaptures++;
            }

            // Log structured information
            _logger.LogInformation(
                "Captured {EventType}: {Image} (PID {Pid}) - ProcessGuid: {ProcessGuid}",
                record.Kind, record.Image, record.Pid, record.ProcessGuid);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to process a Sysmon event.");
        }
    }

    /// <summary>
    /// Checks the digital signature status of an executable file.
    /// Returns a human-readable summary like "Signed - CN=Microsoft Corporation" or "Unsigned".
    /// </summary>
    private static string? GetFileSignatureStatus(string imagePath)
    {
        try
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                return "File not found";

            var cert = X509Certificate.CreateFromSignedFile(imagePath);
            if (cert == null)
                return "Unsigned";

            // Extract subject name for human-readable output
            var subject = cert.Subject;
            // Try to get a cleaner subject using X509Certificate2
            try
            {
                var cert2 = new X509Certificate2(cert);
                var cn = cert2.SubjectName.Format(false);
                if (!string.IsNullOrEmpty(cn))
                    return $"Signed - {cn}";
            }
            catch { /* Fall back to full subject */ }

            return $"Signed - {subject}";
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // File doesn't have a signature or signature is invalid
            return "Unsigned or invalid signature";
        }
        catch (Exception ex)
        {
            return $"Signature check failed: {ex.Message}";
        }
    }

    /// <summary>
    /// Checks if the file is signed by Microsoft or Sysinternals.
    /// Used as a trusted-publisher shortcut for benign classification.
    /// </summary>
    private static bool CheckMicrosoftOrSysinternalsSignature(string imagePath)
    {
        try
        {
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
                return false;

            var cert = X509Certificate.CreateFromSignedFile(imagePath);
            if (cert == null)
                return false;

            var cert2 = new X509Certificate2(cert);
            var subject = cert2.Subject?.ToUpperInvariant() ?? "";

            // Check for Microsoft or Sysinternals publishers
            return subject.Contains("MICROSOFT") || subject.Contains("SYSINTERALS");
        }
        catch
        {
            return false;
        }
    }

    private bool IsTargetProcess(string image)
    {
        if (string.IsNullOrEmpty(image)) return false;
        return _config.TargetImages.Any(t => image.EndsWith(t, StringComparison.OrdinalIgnoreCase));
    }

    private static string TruncateString(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length <= maxLength ? value : value[..maxLength];
    }

    private void WriteCaptureRecord(CaptureRecord record)
    {
        var json = JsonSerializer.Serialize(record);
        var captureFile = _config.CaptureFilePath;

        lock (_stateLock)
        {
            RotateLogFileIfNeeded();
            File.AppendAllText(captureFile, json + Environment.NewLine);
        }
    }

    private void RotateLogFileIfNeeded()
    {
        try
        {
            var captureFile = _config.CaptureFilePath;
            if (!File.Exists(captureFile)) return;

            var fileInfo = new FileInfo(captureFile);
            if (fileInfo.Length < _config.MaxFileSizeBytes) return;

            string archivedName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.jsonl";
            string archivedPath = Path.Combine(_config.LogDirectory, archivedName);
            File.Move(captureFile, archivedPath);

            _logger.LogInformation("Log rotated: {OldFile} -> {NewFile} ({Size} bytes)",
                captureFile, archivedPath, fileInfo.Length);

            // Run cleanup after rotation
            CleanupOldFiles();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to rotate log file. Continuing with current file.");
        }
    }

    private void CleanupOldFiles()
    {
        try
        {
            var logDir = _config.LogDirectory;
            var retentionDays = _config.RetentionDays;
            var cutoff = DateTime.Now.AddDays(-retentionDays);

            var files = Directory.GetFiles(logDir, "capture_*.jsonl");
            foreach (var file in files)
            {
                var info = new FileInfo(file);
                if (info.CreationTime < cutoff)
                {
                    info.Delete();
                    _logger.LogInformation("Cleaned up old log: {File}", file);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to cleanup old log files.");
        }
    }

    private async Task MonitorHealthAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);

                int captures;
                DateTime lastEvent;

                lock (_stateLock)
                {
                    captures = _totalCaptures;
                    lastEvent = _lastEventTime;
                }

                var timeSinceLastEvent = DateTime.UtcNow - lastEvent;

                _logger.LogInformation(
                    "Health check - Total captures: {Count}, Last event: {TimeSinceLastEvent} ago",
                    captures, timeSinceLastEvent);

                // Alert if no events for 10 minutes (potential issue)
                if (captures > 0 && timeSinceLastEvent > TimeSpan.FromMinutes(10))
                {
                    _logger.LogWarning(
                        "No Sysmon events received in {Minutes} minutes. Is Sysmon still running?",
                        timeSinceLastEvent.TotalMinutes);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Health check failed");
            }
        }
    }

    public override void Dispose()
    {
        _watcher?.Dispose();
        base.Dispose();
    }
}