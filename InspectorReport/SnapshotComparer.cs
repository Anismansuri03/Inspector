using System.Text;
using System.Text.Json;
using System.Text.Encodings.Web;

namespace Inspector.Report;

public class Snapshot
{
    public DateTime TakenUtc { get; set; }
    public List<SnapshotEntry> Entries { get; set; } = new();
}

public class SnapshotEntry
{
    public string Source { get; set; } = "";
    public string Name { get; set; } = "";
    public string Command { get; set; } = "";
    public bool KnownBenign { get; set; }
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = "low";
}

public class SnapshotDiff
{
    public Snapshot Before { get; set; } = new();
    public Snapshot After { get; set; } = new();
    public List<SnapshotEntry> Added { get; set; } = new();
    public List<SnapshotEntry> Removed { get; set; } = new();
    public List<(SnapshotEntry Before, SnapshotEntry After)> Changed { get; set; } = new();
    public List<SnapshotEntry> Unchanged { get; set; } = new();
}

/// <summary>
/// Serializes the scored autostart inventory to a JSON snapshot and diffs two
/// snapshots (Added / Removed / Changed / Unchanged) for console and HTML.
/// </summary>
public static class SnapshotComparer
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string TakeSnapshot(List<AutostartEntry> entries)
    {
        var snap = new Snapshot
        {
            TakenUtc = DateTime.UtcNow,
            Entries = entries.Select(e => new SnapshotEntry
            {
                Source = e.Source,
                Name = e.Name,
                Command = e.Command,
                KnownBenign = e.KnownBenign,
                RiskScore = e.RiskScore,
                RiskLevel = e.RiskLevel
            }).OrderBy(e => e.Source, StringComparer.OrdinalIgnoreCase)
              .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
              .ToList()
        };
        return JsonSerializer.Serialize(snap, JsonOpts);
    }

    public static Snapshot Load(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<Snapshot>(json, JsonOpts)
               ?? throw new InvalidDataException($"Invalid snapshot file: {path}");
    }

    public static SnapshotDiff Diff(Snapshot before, Snapshot after)
    {
        var diff = new SnapshotDiff { Before = before, After = after };
        var beforeMap = ToMap(before.Entries);
        var afterMap = ToMap(after.Entries);

        foreach (var (key, entry) in afterMap)
        {
            if (!beforeMap.TryGetValue(key, out var old))
                diff.Added.Add(entry);
            else if (!string.Equals(old.Command, entry.Command, StringComparison.OrdinalIgnoreCase))
                diff.Changed.Add((old, entry));
            else
                diff.Unchanged.Add(entry);
        }

        foreach (var (key, entry) in beforeMap)
        {
            if (!afterMap.ContainsKey(key))
                diff.Removed.Add(entry);
        }

        return diff;
    }

    private static Dictionary<string, SnapshotEntry> ToMap(List<SnapshotEntry> entries)
    {
        var map = new Dictionary<string, SnapshotEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in entries)
        {
            var key = Key(e);
            if (!map.ContainsKey(key))
                map[key] = e;
        }
        return map;
    }

    public static string RenderConsole(SnapshotDiff diff)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"added={diff.Added.Count}  removed={diff.Removed.Count}  changed={diff.Changed.Count}  unchanged={diff.Unchanged.Count}");

        if (diff.Added.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Added:");
            foreach (var e in diff.Added.OrderBy(x => x.Source).ThenBy(x => x.Name))
                sb.AppendLine($"  + [{e.Source}] {e.Name}");
        }
        if (diff.Removed.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Removed:");
            foreach (var e in diff.Removed.OrderBy(x => x.Source).ThenBy(x => x.Name))
                sb.AppendLine($"  - [{e.Source}] {e.Name}");
        }
        if (diff.Changed.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Changed:");
            foreach (var (old, neu) in diff.Changed)
            {
                sb.AppendLine($"  ~ [{neu.Source}] {neu.Name}");
                sb.AppendLine($"      before: {Truncate(old.Command, 120)}");
                sb.AppendLine($"      after:  {Truncate(neu.Command, 120)}");
            }
        }
        return sb.ToString();
    }

    public static string RenderHtml(SnapshotDiff diff)
    {
        static string Enc(string? s) => System.Text.Encodings.Web.HtmlEncoder.Default.Encode(s ?? "");

        var sb = new StringBuilder();
        sb.Append("""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Inspector - Autostart Comparison</title>
        <style>
          :root { --bg:#0b0d12; --panel:#12151c; --border:#232838; --text:#e7eaf0; --muted:#8b93a7;
                  --green:#55d497; --red:#ff6b6b; --amber:#e8b84b; --accent:#5b8cff; }
          * { box-sizing:border-box; }
          body { font-family:-apple-system,"Segoe UI",Inter,Arial,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:0 0 60px; line-height:1.5; }
          .wrap { max-width:980px; margin:0 auto; padding:36px 24px; }
          h1 { font-size:28px; margin:6px 0 4px; letter-spacing:-0.02em; }
          .meta { color:var(--muted); font-size:13.5px; margin-bottom:24px; }
          .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:26px; }
          .stat { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:16px 18px; }
          .stat .n { font-size:26px; font-weight:700; line-height:1; }
          .stat .l { color:var(--muted); font-size:12px; margin-top:6px; text-transform:uppercase; letter-spacing:.04em; }
          .stat.added .n { color:var(--green); } .stat.removed .n { color:var(--red); }
          .stat.changed .n { color:var(--amber); } .stat.unchanged .n { color:var(--muted); }
          .section-title { font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin:22px 0 10px; }
          .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:12px 14px; margin-bottom:8px; }
          .card .name { font-weight:600; font-size:14px; }
          .card .src { color:var(--muted); font-size:11.5px; text-transform:uppercase; letter-spacing:.04em; }
          .mono { font-family:"SF Mono",Consolas,monospace; font-size:12.5px; color:#c7d0dc; background:#171b24;
                  border:1px solid var(--border); border-radius:8px; padding:8px 10px; word-break:break-all; margin-top:8px; }
          .tag { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; margin-left:8px; }
          .tag-add { background:#0f2118; color:var(--green); border:1px solid #1f4a34; }
          .tag-del { background:#2a1416; color:var(--red); border:1px solid #5c2226; }
          .tag-chg { background:#251f0f; color:var(--amber); border:1px solid #4d3f16; }
          @media (max-width:720px){ .stats{ grid-template-columns:1fr 1fr; } }
        </style></head><body><div class="wrap">
        """);

        sb.Append($"""
        <div class="meta">Autostart comparison</div>
        <h1>Startup Change Report</h1>
        <div class="meta">Before: {diff.Before.TakenUtc:u} &nbsp;&middot;&nbsp; After: {diff.After.TakenUtc:u}</div>
        <div class="stats">
          <div class="stat added"><div class="n">{diff.Added.Count}</div><div class="l">Added</div></div>
          <div class="stat removed"><div class="n">{diff.Removed.Count}</div><div class="l">Removed</div></div>
          <div class="stat changed"><div class="n">{diff.Changed.Count}</div><div class="l">Changed</div></div>
          <div class="stat unchanged"><div class="n">{diff.Unchanged.Count}</div><div class="l">Unchanged</div></div>
        </div>
        """);

        AppendSection(sb, "Added", diff.Added.OrderBy(x => x.Source).ThenBy(x => x.Name),
            e => $"<span class='tag tag-add'>new</span>", e => null);
        AppendSection(sb, "Removed", diff.Removed.OrderBy(x => x.Source).ThenBy(x => x.Name),
            e => $"<span class='tag tag-del'>gone</span>", e => null);
        if (diff.Changed.Count > 0)
        {
            sb.Append("<div class='section-title'>Changed</div>");
            foreach (var (old, neu) in diff.Changed)
            {
                sb.Append($"""
                <div class="card">
                  <div class="src">{Enc(neu.Source)}</div>
                  <div class="name">{Enc(neu.Name)}<span class="tag tag-chg">changed</span></div>
                  <div class="mono"><b>before:</b> {Enc(old.Command)}</div>
                  <div class="mono"><b>after:</b>&nbsp;&nbsp; {Enc(neu.Command)}</div>
                </div>
                """);
            }
        }

        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    private static void AppendSection(
        StringBuilder sb,
        string title,
        IEnumerable<SnapshotEntry> entries,
        Func<SnapshotEntry, string> tag,
        Func<SnapshotEntry, string?> _)
    {
        var list = entries.ToList();
        if (list.Count == 0) return;
        static string Enc(string? s) => System.Text.Encodings.Web.HtmlEncoder.Default.Encode(s ?? "");
        sb.Append($"<div class='section-title'>{title}</div>");
        foreach (var e in list)
        {
            sb.Append($"""
            <div class="card">
              <div class="src">{Enc(e.Source)}</div>
              <div class="name">{Enc(e.Name)}{tag(e)}</div>
              <div class="mono">{Enc(e.Command)}</div>
            </div>
            """);
        }
    }

    private static string Key(SnapshotEntry e) => $"{e.Source}|{e.Name}";

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max] + "...");
}
