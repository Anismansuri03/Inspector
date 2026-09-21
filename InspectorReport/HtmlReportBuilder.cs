using System.Text;
using System.Text.Encodings.Web;
using System.Management;
using Inspector.Common;

namespace Inspector.Report;

public static class HtmlReportBuilder
{
    public static void Build(List<MergedEvent> events, List<AutostartEntry> autostart, string outPath)
    {
        int flaggedCount = events.Count(e => e.RiskLevel == "investigate");
        int benignCount = events.Count(e => e.RiskLevel == "benign");
        int autostartFlagged = autostart.Count(a => !a.KnownBenign);

        // System info
        string machineName = Environment.MachineName;
        string osVersion = Environment.OSVersion.VersionString;
        string user = Environment.UserDomainName + "\\" + Environment.UserName;
        string ReportTime = DateTime.Now.ToString("dddd, dd MMMM yyyy - HH:mm:ss");

        // Capture frequency stats
        var capturesPerDay = events
            .GroupBy(e => e.Create.TimeUtc.ToLocalTime().Date)
            .OrderByDescending(g => g.Key)
            .ToList();
        int totalDays = capturesPerDay.Count;
        double avgPerDay = totalDays > 0 ? (double)events.Count / totalDays : 0;

        var busiestHour = events
            .GroupBy(e => e.Create.TimeUtc.ToLocalTime().Hour)
            .OrderByDescending(g => g.Count())
            .FirstOrDefault();
        string busiestHourStr = busiestHour != null ? $"{busiestHour.Key:00}:00 - {busiestHour.Key:00}:59" : "N/A";

        var sb = new StringBuilder();
        sb.Append("""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Inspector Report</title>
        <style>
          :root {
            --bg: #0b0d12; --panel: #12151c; --panel-2: #171b24; --border: #232838;
            --text: #e7eaf0; --muted: #8b93a7; --accent: #5b8cff;
            --red: #ff6b6b; --red-bg: #2a1416; --red-bd: #5c2226;
            --amber: #e8b84b; --amber-bg: #251f0f; --amber-bd: #4d3f16;
            --green: #55d497; --green-bg: #0f2118; --green-bd: #1f4a34;
          }
          * { box-sizing: border-box; }
          body {
            font-family: -apple-system, "Segoe UI", Inter, Arial, sans-serif;
            background: radial-gradient(1200px 600px at 10% -10%, #141a26 0%, var(--bg) 55%);
            color: var(--text); margin: 0; padding: 0 0 60px; line-height: 1.5;
          }
          .wrap { max-width: 980px; margin: 0 auto; padding: 36px 24px; }
          header { margin-bottom: 28px; }
          .brand { display:flex; align-items:center; gap:10px; font-size: 14px; color: var(--muted); letter-spacing:.06em; text-transform:uppercase; font-weight:600; }
          h1 { font-size: 30px; margin: 6px 0 4px; letter-spacing:-0.02em; }
          .meta { color: var(--muted); font-size: 13.5px; }

          .sysinfo { display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 20px 0 26px; }
          .sysinfo-item { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
          .sysinfo-item .label { color: var(--muted); font-size: 11px; text-transform:uppercase; letter-spacing:.04em; margin-bottom: 4px; }
          .sysinfo-item .value { font-size: 13.5px; font-weight: 500; word-break: break-all; }

          .stats { display:grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 26px 0 30px; }
          .stat { background: var(--panel); border:1px solid var(--border); border-radius: 14px; padding: 16px 18px; }
          .stat .n { font-size: 26px; font-weight: 700; line-height:1; }
          .stat .l { color: var(--muted); font-size: 12px; margin-top:6px; text-transform:uppercase; letter-spacing:.04em; }
          .stat.warn .n { color: var(--red); }
          .stat.ok .n { color: var(--green); }

          .freq-stats { display:grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 0 0 26px; }
          .freq-stat { background: var(--panel); border:1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
          .freq-stat .label { color: var(--muted); font-size: 11px; text-transform:uppercase; letter-spacing:.04em; margin-bottom: 4px; }
          .freq-stat .value { font-size: 15px; font-weight: 600; }

          .tabs { display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:18px; position:sticky; top:0; background: var(--bg); padding-top:6px; z-index:5; }
          .tab { padding:10px 16px; cursor:pointer; color:var(--muted); font-size:14px; font-weight:600; border-bottom:2px solid transparent; user-select:none; }
          .tab.active { color: var(--text); border-bottom-color: var(--accent); }
          .panel-view { display:none; } .panel-view.active { display:block; }

          input#search {
            width:100%; padding:11px 14px; margin-bottom:18px; border-radius:10px;
            border:1px solid var(--border); background: var(--panel); color:var(--text); font-size:14px;
          }
          input#search:focus { outline:none; border-color: var(--accent); }

          .empty { text-align:center; padding: 60px 20px; color: var(--muted); background: var(--panel); border:1px solid var(--border); border-radius:14px; }
          .empty .big { font-size: 34px; margin-bottom: 10px; }

          .date-header {
            font-size: 14px; font-weight: 700; color: var(--accent); margin: 24px 0 10px;
            padding-bottom: 6px; border-bottom: 1px solid var(--border);
          }
          .date-header:first-child { margin-top: 0; }
          .date-count { color: var(--muted); font-weight: 400; font-size: 12px; margin-left: 8px; }

          details.card {
            background: var(--panel); border:1px solid var(--border); border-radius: 12px;
            margin-bottom: 10px; overflow:hidden;
          }
          details.card[open] { border-color:#2c3346; }
          summary.row {
            list-style:none; cursor:pointer; padding:14px 16px; display:flex; align-items:center; gap:12px;
          }
          summary.row::-webkit-details-marker { display:none; }
          .chev { color: var(--muted); font-size:11px; transition: transform .15s; flex-shrink:0; }
          details[open] .chev { transform: rotate(90deg); }

          .badge { display:inline-flex; align-items:center; gap:5px; padding:3px 10px; border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.02em; flex-shrink:0; white-space:nowrap; }
          .badge-investigate { background: var(--red-bg); color: var(--red); border:1px solid var(--red-bd); }
          .badge-unknown { background: var(--amber-bg); color: var(--amber); border:1px solid var(--amber-bd); }
          .badge-benign { background: var(--green-bg); color: var(--green); border:1px solid var(--green-bd); }

          .row-main { flex:1; min-width:0; }
          .row-title { font-weight:600; font-size:14.5px; }
          .row-sub { color: var(--muted); font-size:12.5px; margin-top:2px; }
          .row-time { color: var(--muted); font-size:12px; flex-shrink:0; text-align:right; }

          .body { padding: 4px 16px 18px 42px; border-top:1px solid var(--border); }
          .grid2 { display:grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top:14px; }
          @media (max-width: 720px) { .grid2 { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr 1fr; } .freq-stats { grid-template-columns: 1fr; } .sysinfo { grid-template-columns: 1fr; } }

          .field-label { color: var(--muted); font-size: 11px; text-transform:uppercase; letter-spacing:.05em; margin: 12px 0 4px; }
          .field-label:first-child { margin-top:0; }
          .mono {
            font-family: "SF Mono", Consolas, monospace; font-size: 12.5px; color: #c7d0dc;
            background: var(--panel-2); border:1px solid var(--border); border-radius:8px;
            padding: 8px 10px; word-break: break-all; position:relative;
          }
          .copy-btn {
            position:absolute; top:6px; right:6px; background:var(--panel); border:1px solid var(--border);
            color:var(--muted); font-size:10px; padding:3px 7px; border-radius:6px; cursor:pointer;
          }
          .copy-btn:hover { color: var(--text); }
          .ai-section {
            background: linear-gradient(135deg, rgba(138, 99, 255, 0.08) 0%, rgba(91, 140, 255, 0.08) 100%);
            border: 1px solid rgba(138, 99, 255, 0.25);
            border-radius: 16px;
            padding: 24px;
            margin: 30px 0;
            position: relative;
            overflow: hidden;
          }
          .ai-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #8a63ff 0%, #5b8cff 50%, #55d497 100%);
            opacity: 0.6;
          }
          .ai-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
          }
          .ai-header-icon {
            font-size: 32px;
            line-height: 1;
            filter: drop-shadow(0 2px 8px rgba(138, 99, 255, 0.4));
          }
          .ai-header-text h3 {
            margin: 0;
            font-size: 18px;
            font-weight: 700;
            color: var(--text);
            letter-spacing: -0.01em;
          }
          .ai-header-text p {
            margin: 4px 0 0;
            font-size: 13px;
            color: var(--muted);
            line-height: 1.4;
          }
          .ai-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
          }
          .ai-prompt-btn {
            background: linear-gradient(135deg, rgba(138, 99, 255, 0.15) 0%, rgba(91, 140, 255, 0.15) 100%);
            border: 1.5px solid rgba(138, 99, 255, 0.4);
            color: var(--text);
            padding: 11px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(138, 99, 255, 0.15);
            position: relative;
          }
          .ai-prompt-btn:hover {
            background: linear-gradient(135deg, rgba(138, 99, 255, 0.25) 0%, rgba(91, 140, 255, 0.25) 100%);
            border-color: rgba(138, 99, 255, 0.6);
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(138, 99, 255, 0.3);
          }
          .ai-prompt-btn:active {
            transform: translateY(0);
          }
          .ai-prompt-btn.copied {
            background: linear-gradient(135deg, rgba(85, 212, 151, 0.2) 0%, rgba(76, 175, 80, 0.2) 100%);
            border-color: rgba(85, 212, 151, 0.6);
            color: #55d497;
          }
          .ai-icon {
            font-size: 18px;
            line-height: 1;
          }
          .ai-steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid rgba(138, 99, 255, 0.15);
          }
          .ai-step {
            display: flex;
            align-items: start;
            gap: 8px;
            font-size: 12px;
            color: var(--muted);
            line-height: 1.5;
          }
          .ai-step-num {
            background: rgba(138, 99, 255, 0.2);
            color: #a78bfa;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 11px;
            flex-shrink: 0;
          }
          .trigger-line { margin-top:10px; padding:10px 12px; background:#161227; border:1px solid #2c2450; border-radius:8px; font-size:12.5px; }
          .trigger-line b { color:#b9a6ff; }

          .remediation-section {
            background: var(--panel);
            border: 1px solid var(--red-bd);
            border-radius: 12px;
            padding: 16px 18px;
            margin: 22px 0 10px;
          }
          .remediation-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            font-weight: 700;
            color: var(--red);
            text-transform: uppercase;
            letter-spacing: .04em;
            margin-bottom: 10px;
          }
          .remediation-steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 8px;
          }
          .remediation-step {
            background: var(--panel-2);
            border-radius: 8px;
            padding: 8px 10px;
            font-size: 12px;
            line-height: 1.5;
          }
          .remediation-step code {
            font-family: "SF Mono", Consolas, monospace;
            background: rgba(255,255,255,0.05);
            padding: 1px 4px;
            border-radius: 3px;
            color: #ff8e8e;
          }

          .section-title { font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.05em; margin: 22px 0 10px; }
          .section-title:first-child { margin-top:0; }
        </style></head><body><div class="wrap">
        """);

        sb.Append($"""
        <header>
          <div class="brand">&#128737;&#65039; Inspector</div>
          <h1>Startup Activity Report</h1>
          <div class="meta">Generated {ReportTime}</div>
        </header>

        <div class="sysinfo">
          <div class="sysinfo-item">
            <div class="label">Machine</div>
            <div class="value">{HtmlEncode(machineName)}</div>
          </div>
          <div class="sysinfo-item">
            <div class="label">OS</div>
            <div class="value">{HtmlEncode(osVersion)}</div>
          </div>
          <div class="sysinfo-item">
            <div class="label">Run as</div>
            <div class="value">{HtmlEncode(user)}</div>
          </div>
          <div class="sysinfo-item">
            <div class="label">Report generated</div>
            <div class="value">{ReportTime}</div>
          </div>
        </div>

        <div class="stats">
          <div class="stat"><div class="n">{events.Count}</div><div class="l">Processes captured</div></div>
          <div class="stat {(flaggedCount > 0 ? "warn" : "")}"><div class="n">{flaggedCount}</div><div class="l">Flagged to investigate</div></div>
          <div class="stat ok"><div class="n">{benignCount}</div><div class="l">Confirmed benign</div></div>
          <div class="stat {(autostartFlagged > 0 ? "warn" : "")}"><div class="n">{autostart.Count}</div><div class="l">Autostart entries scanned</div></div>
        </div>

        <div class="freq-stats">
          <div class="freq-stat">
            <div class="label">Active days</div>
            <div class="value">{totalDays}</div>
          </div>
          <div class="freq-stat">
            <div class="label">Avg captures / day</div>
            <div class="value">{avgPerDay:F1}</div>
          </div>
          <div class="freq-stat">
            <div class="label">Busiest hour</div>
            <div class="value">{busiestHourStr}</div>
          </div>
        </div>

        <div class="ai-section">
          <div class="ai-header">
            <div class="ai-header-icon">🤖</div>
            <div class="ai-header-text">
              <h3>AI Security Analysis</h3>
              <p>Get instant, plain-English security assessment from ChatGPT, Claude, or any AI assistant</p>
            </div>
          </div>
          <div class="ai-actions">
            <button class="ai-prompt-btn" onclick="generateAndCopyReportPrompt(this)">
              <span class="ai-icon">📋</span> Copy Analysis Prompt
            </button>
          </div>
          <div class="ai-steps">
            <div class="ai-step">
              <span class="ai-step-num">1</span>
              <span>Click button to copy prompt</span>
            </div>
            <div class="ai-step">
              <span class="ai-step-num">2</span>
              <span>Upload this HTML file to your AI</span>
            </div>
            <div class="ai-step">
              <span class="ai-step-num">3</span>
              <span>Paste the prompt text</span>
            </div>
            <div class="ai-step">
              <span class="ai-step-num">4</span>
              <span>Get comprehensive security summary</span>
            </div>
          </div>
        </div>

        <div class="tabs">
          <div class="tab active" onclick="showTab('captures')">Process Launches ({events.Count})</div>
          <div class="tab" onclick="showTab('autostart')">Autostart Inventory ({autostart.Count})</div>
        </div>

        <input id="search" placeholder="Filter by process, command line, user..." oninput="filterCards()">
        """);

        // ---- Captures tab ----
        sb.Append("<div id='captures' class='panel-view active'>");
        if (events.Count == 0)
        {
            sb.Append("""
            <div class="empty">
              <div class="big">&#128064;</div>
              <div><b>Nothing captured yet.</b></div>
              <div style="margin-top:6px;">The watcher is armed and listening. Once the popup happens again, run <code>-Report</code> to see it here.</div>
            </div>
            """);
        }
        else
        {
            // Group events by date
            var grouped = events
                .GroupBy(e => e.Create.TimeUtc.ToLocalTime().Date)
                .OrderByDescending(g => g.Key);

            foreach (var dayGroup in grouped)
            {
                string dateLabel = dayGroup.Key.ToString("dddd, dd MMMM yyyy");
                int dayCount = dayGroup.Count();
                sb.Append($"<div class='date-header'>{HtmlEncode(dateLabel)}<span class='date-count'>{dayCount} capture{(dayCount != 1 ? "s" : "")}</span></div>");

                foreach (var ev in dayGroup.OrderByDescending(e => e.Create.TimeUtc))
                {
                    var c = ev.Create;
                    var (badgeClass, badgeText, icon) = ev.RiskLevel switch
                    {
                        "investigate" => ("badge-investigate", "INVESTIGATE", "&#9888;&#65039;"),
                        "benign" => ("badge-benign", "benign", "&#9989;"),
                        _ => ("badge-unknown", "unrecognized", "&#10067;")
                    };
                    string lifetime = ev.LifetimeMs.HasValue ? $"{ev.LifetimeMs.Value:0} ms" : "no exit captured";
                    string searchBlob = HtmlEncode($"{c.Image} {c.CommandLine} {c.User} {c.ParentImage} {c.ParentCommandLine}").ToLowerInvariant();
                    string procName = HtmlEncode(Path.GetFileName(c.Image));

                    sb.Append($"""
                    <details class="card" data-search="{searchBlob}">
                      <summary class="row">
                        <span class="chev">&#9656;</span>
                        <span class="badge {badgeClass}">{icon} {badgeText}</span>
                        <div class="row-main">
                          <div class="row-title">{procName}</div>
                          <div class="row-sub">alive {lifetime}{(ev.LikelyTrigger != null ? " - triggered by " + HtmlEncode(ShortTrigger(ev.LikelyTrigger)) : "")}</div>
                        </div>
                        <div class="row-time">{c.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}</div>
                      </summary>
                      <div class="body">
                        {(ev.LikelyTrigger != null ? $"<div class='trigger-line'>&#128681; Likely triggered by <b>{HtmlEncode(ev.LikelyTrigger)}</b></div>" : "")}
                        <div class="grid2">
                          <div>
                            <div class="field-label">Command line</div>
                            <div class="mono">{CopyBtn()}{HtmlEncode(c.CommandLine ?? "(none)")}</div>
                            <div class="field-label">Parent process</div>
                            <div class="mono">{HtmlEncode(c.ParentImage ?? "?")} &rarr; {HtmlEncode(c.ParentCommandLine ?? "(none)")}</div>
                            {(ev.AncestorChain?.Any() == true ? $@"
                            <div class=""field-label"">Parent chain (ancestors)</div>
                            <div class=""mono"">{CopyBtn()}{string.Join(" &rarr; ", ev.AncestorChain.Select(HtmlEncode))}</div>" : "")}
                          </div>
                          <div>
                            <div class="field-label">User &middot; Integrity level</div>
                            <div class="mono">{HtmlEncode(c.User ?? "?")} &middot; {HtmlEncode(c.IntegrityLevel ?? "?")}</div>
                            <div class="field-label">Publisher / file info</div>
                            <div class="mono">{CopyBtn()}{HtmlEncode(c.SignedStatus ?? "signature unknown")}</div>
                            <div class="field-label">Company</div>
                            <div class="mono">{HtmlEncode(c.Company ?? "Unknown company")} &middot; {HtmlEncode(c.OriginalFileName ?? "no original filename recorded")}</div>
                            <div class="field-label">Hash</div>
                            <div class="mono">{CopyBtn()}{HtmlEncode(c.Hashes ?? "none")}</div>
                          </div>
                        </div>
                        {(ev.RiskLevel == "investigate" ? $@"
                        <div class='remediation-section'>
                          <div class='remediation-title'>&#9888;&#65039; What should I do next?</div>
                          <div class='remediation-steps'>
                            {GenerateRemediationSteps(ev)}
                          </div>
                        </div>" : "")}
                      </div>
                    </details>
                    """);
                }
            }
        }
        sb.Append("</div>");

        // ---- Autostart tab ----
        sb.Append("<div id='autostart' class='panel-view'>");
        var groups = autostart.GroupBy(a => a.Source).OrderBy(g => g.Key);
        foreach (var group in groups)
        {
            sb.Append($"<div class='section-title'>{HtmlEncode(group.Key)}</div>");
            foreach (var a in group.OrderByDescending(x => !x.KnownBenign))
            {
                string badgeClass = a.KnownBenign ? "badge-benign" : "badge-unknown";
                string badgeText = a.KnownBenign ? "benign" : "check this";
                string icon = a.KnownBenign ? "&#9989;" : "&#128269;";
                sb.Append($"""
                <details class="card">
                  <summary class="row">
                    <span class="chev">&#9656;</span>
                    <span class="badge {badgeClass}">{icon} {badgeText}</span>
                    <div class="row-main">
                      <div class="row-title">{HtmlEncode(a.Name)}</div>
                    </div>
                  </summary>
                  <div class="body">
                    <div class="field-label">Full command / definition</div>
                    <div class="mono">{CopyBtn()}{HtmlEncode(a.Command)}</div>
                  </div>
                </details>
                """);
            }
        }
        sb.Append("</div>");

        sb.Append("""
        </div>
        <script>
        function showTab(id) {
          document.querySelectorAll('.panel-view').forEach(p => p.classList.remove('active'));
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.getElementById(id).classList.add('active');
          event.target.classList.add('active');
        }
        function filterCards(){
          const q = document.getElementById('search').value.toLowerCase();
          document.querySelectorAll('#captures .card').forEach(c => {
            c.style.display = (c.dataset.search || '').includes(q) ? '' : 'none';
          });
        }
        function copyText(btn){
          const block = btn.parentElement;
          const text = block.innerText.replace('Copy','').trim();
          navigator.clipboard.writeText(text).then(() => {
            btn.innerText = 'Copied';
            setTimeout(() => btn.innerText = 'Copy', 1200);
          });
        }
        function generateAndCopyReportPrompt(btn) {
          // Extract report data from the page
          const stats = document.querySelectorAll('.stat .n');
          const totalProcesses = stats[0]?.textContent || '0';
          const flaggedCount = stats[1]?.textContent || '0';
          const benignCount = stats[2]?.textContent || '0';
          const autostartCount = stats[3]?.textContent || '0';

          const sysinfo = document.querySelectorAll('.sysinfo-item .value');
          const machineName = sysinfo[0]?.textContent || 'Unknown';
          const osVersion = sysinfo[1]?.textContent || 'Unknown';
          const runAsUser = sysinfo[2]?.textContent || 'Unknown';
          const reportTime = sysinfo[3]?.textContent || new Date().toLocaleString();

          const freqStats = document.querySelectorAll('.freq-stat .value');
          const activeDays = freqStats[0]?.textContent || '?';
          const avgPerDay = freqStats[1]?.textContent || '?';
          const busiestHour = freqStats[2]?.textContent || 'N/A';

          // Collect suspicious events from INVESTIGATE cards
          const suspiciousCards = [];
          document.querySelectorAll('#captures .card').forEach(card => {
            const badge = card.querySelector('.badge-investigate');
            if (badge) {
              const title = card.querySelector('.row-title')?.textContent || 'Unknown';
              const subtext = card.querySelector('.row-sub')?.textContent || '';
              const timestamp = card.querySelector('.row-time')?.textContent || 'Unknown';

              const commandLine = card.querySelectorAll('.mono')[0]?.textContent?.replace('Copy', '').trim() || 'N/A';
              const parentProcess = card.querySelectorAll('.mono')[1]?.textContent?.replace('Copy', '').trim() || 'N/A';
              const user = card.querySelectorAll('.mono')[2]?.textContent?.replace('Copy', '').trim() || 'N/A';
              const publisher = card.querySelectorAll('.mono')[3]?.textContent?.replace('Copy', '').trim() || 'N/A';
              const hash = card.querySelectorAll('.mono')[4]?.textContent?.replace('Copy', '').trim() || 'N/A';

              suspiciousCards.push({
                process: title,
                details: subtext,
                time: timestamp,
                command: commandLine,
                parent: parentProcess,
                user: user,
                publisher: publisher,
                hash: hash
              });
            }
          });

          // Build the AI prompt
          const prompt = buildAIPrompt({
            machine: machineName,
            os: osVersion,
            user: runAsUser,
            reportTime: reportTime,
            totalProcesses: totalProcesses,
            flaggedCount: flaggedCount,
            benignCount: benignCount,
            autostartCount: autostartCount,
            activeDays: activeDays,
            avgPerDay: avgPerDay,
            busiestHour: busiestHour,
            suspiciousEvents: suspiciousCards.slice(0, 5)
          });

          // Copy to clipboard
          navigator.clipboard.writeText(prompt).then(() => {
            btn.classList.add('copied');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="ai-icon">✅</span> Copied! Upload HTML + paste prompt';
            setTimeout(() => {
              btn.innerHTML = originalText;
              btn.classList.remove('copied');
            }, 3500);
          }).catch((err) => {
            // Fallback: create textarea and select text
            const textarea = document.createElement('textarea');
            textarea.value = prompt;
            document.body.appendChild(textarea);
            textarea.select();
            textarea.setSelectionRange(0, 99999);
            document.execCommand('copy');
            document.body.removeChild(textarea);
            btn.classList.add('copied');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="ai-icon">✅</span> Copied! Upload HTML + paste prompt';
            setTimeout(() => {
              btn.innerHTML = originalText;
              btn.classList.remove('copied');
            }, 3500);
          });
        }

        function buildAIPrompt(data) {
          let prompt = `📄 IMPORTANT: Please upload the HTML report file along with this prompt for complete analysis.\n\n`;
          prompt += `I need a comprehensive security analysis of this Windows system activity report from Inspector (a Sysmon monitoring tool).\n\n`;
          prompt += `🔍 **INSTRUCTIONS:**\n`;
          prompt += `1. First, upload the HTML report file that came with this prompt\n`;
          prompt += `2. Review the attached HTML file for complete details\n`;
          prompt += `3. Use the summary below as a quick reference\n`;
          prompt += `4. Provide a comprehensive security assessment\n\n`;

          prompt += `**REPORT OVERVIEW:**\n`;
          prompt += `- Machine: ${data.machine}\n`;
          prompt += `- OS: ${data.os}\n`;
          prompt += `- Report Time: ${data.reportTime}\n`;
          prompt += `- Total Processes Captured: ${data.totalProcesses}\n`;
          prompt += `- ⚠️ INVESTIGATE: ${data.flaggedCount} (High risk - needs immediate attention)\n`;
          prompt += `- ❓ UNKNOWN: ${data.totalProcesses - data.flaggedCount - data.benignCount} (Medium risk - requires investigation)\n`;
          prompt += `- ✅ BENIGN: ${data.benignCount} (Low risk - normal/trusted)\n`;
          prompt += `- Autostart Entries Scanned: ${data.autostartCount}\n`;
          prompt += `- Active Days: ${data.activeDays}, Avg/Day: ${data.avgPerDay}, Busiest Hour: ${data.busiestHour}\n\n`;

          if (data.suspiciousEvents.length > 0) {
            prompt += `**TOP SUSPICIOUS EVENTS (Need Immediate Attention):**\n`;
            data.suspiciousEvents.forEach((event, i) => {
              prompt += `${i+1}. **${event.process}** - ${event.details}\n`;
              prompt += `   Command: ${event.command}\n`;
              prompt += `   User: ${event.user}, Time: ${event.time}\n`;
              prompt += `   Publisher/Hash: ${event.publisher} / ${event.hash}\n`;
              prompt += `   Parent: ${event.parent}\n\n`;
            });
          }

          prompt += `**ANALYSIS REQUESTED:**\n`;
          prompt += `1. **OVERALL SYSTEM HEALTH**: Rate the overall security health (Excellent/Good/Concerning/Critical)\n`;
          prompt += `2. **IMMEDIATE RISKS**: What are the most dangerous findings that need attention NOW?\n`;
          prompt += `3. **PATTERNS DETECTED**: Are there suspicious patterns (time-based, user-based, process-based)?\n`;
          prompt += `4. **RECOMMENDED ACTIONS**: Provide clear next steps with priorities:\n`;
          prompt += `   a) Immediate actions (today)\n`;
          prompt += `   b) Short-term actions (this week)\n`;
          prompt += `   c) Long-term improvements\n`;
          prompt += `5. **BENIGN ACTIVITY**: What normal activity should I NOT worry about?\n`;
          prompt += `6. **FOR NON-TECHNICAL USERS**: Explain in simple terms what this means for my computer's safety.\n\n`;
          prompt += `Please provide a comprehensive yet easy-to-understand security summary suitable for both technical and non-technical users. Include specific, actionable recommendations based on the uploaded HTML report.`;

          return prompt;
        }
        </script>
        </body></html>
        """);

        File.WriteAllText(outPath, sb.ToString());
    }

    private static string CopyBtn() => "<span class=\"copy-btn\" onclick=\"copyText(this)\">Copy</span>";

    private static string ShortTrigger(string trigger)
    {
        var idx = trigger.IndexOf(']');
        return idx >= 0 && idx + 1 < trigger.Length ? trigger[(idx + 1)..].Trim() : trigger;
    }

    /// <summary>
    /// Generates actionable remediation steps based on the risk category of the event.
    /// Each category gets specific guidance on what to check, disable, or investigate.
    /// </summary>
    private static string GenerateRemediationSteps(MergedEvent ev)
    {
        var c = ev.Create;
        var commandLower = (c.CommandLine ?? "").ToLowerInvariant();
        var procName = Path.GetFileName(c.Image ?? "").ToLowerInvariant();
        var parentName = Path.GetFileName(c.ParentImage ?? "").ToLowerInvariant();
        var steps = new List<string>();

        // --- Run Key remediation ---
        if (!string.IsNullOrEmpty(ev.LikelyTrigger) && ev.LikelyTrigger.Contains("Run Key"))
        {
            steps.Add($"<div class='remediation-step'>Check the Run key in <code>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run</code> and remove any entries referencing <b>{HtmlEncode(procName)}</b></div>");
        }

        // --- Scheduled Task remediation ---
        if (!string.IsNullOrEmpty(ev.LikelyTrigger) && ev.LikelyTrigger.Contains("Scheduled Task"))
        {
            steps.Add($"<div class='remediation-step'>Review Task Scheduler: <code>taskschd.msc</code> &rarr; find the task referencing <b>{HtmlEncode(procName)}</b> &rarr; disable it</div>");
        }

        // --- WMI remediation ---
        if (!string.IsNullOrEmpty(ev.LikelyTrigger) && ev.LikelyTrigger.Contains("WMI"))
        {
            steps.Add($"<div class='remediation-step'>Check WMI event consumers: <code>Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer</code> and remove suspicious entries</div>");
        }

        // --- PowerShell suspicious usage ---
        if (procName.Contains("powershell") || commandLower.Contains("-enc") || commandLower.Contains("-encodedcommand") || commandLower.Contains("iex") || commandLower.Contains("invoke-expression"))
        {
            steps.Add($"<div class='remediation-step'>Investigate PowerShell usage in <code>Microsoft-Windows-PowerShell/Operational</code> event log for full script block logging</div>");
        }

        // --- CMD suspicious usage ---
        if (procName == "cmd.exe" && (commandLower.Contains("/c") || commandLower.Contains("powershell") || commandLower.Contains("wscript")))
        {
            steps.Add($"<div class='remediation-step'>CMD spawned another script engine &mdash; check if this is legitimate installer behavior or suspicious chaining</div>");
        }

        // --- mshta.exe ---
        if (procName == "mshta.exe")
        {
            steps.Add($"<div class='remediation-step'><b>mshta.exe</b> is rarely needed legitimately &mdash; block it in Windows Defender Application Control or AppLocker if unused</div>");
        }

        // --- regsvr32.exe ---
        if (procName == "regsvr32.exe")
        {
            steps.Add($"<div class='remediation-step'><b>regsvr32.exe</b> with remote URLs is a common living-off-the-land technique &mdash; check for <code>/s</code> + URL patterns and block in your perimeter firewall</div>");
        }

        // --- rundll32.exe ---
        if (procName == "rundll32.exe")
        {
            steps.Add($"<div class='remediation-step'>Verify the DLL being loaded is legitimate &mdash; <code>rundll32.exe</code> loading from temp dirs or with unusual entry points is suspicious</div>");
        }

        // --- certutil.exe ---
        if (procName == "certutil.exe")
        {
            steps.Add($"<div class='remediation-step'><b>certutil.exe</b> with <code>-urlcache</code> or <code>-decode</code> is often used to download/execute payloads &mdash; check network logs and block if found</div>");
        }

        // --- bitsadmin.exe ---
        if (procName == "bitsadmin.exe")
        {
            steps.Add($"<div class='remediation-step'><b>bitsadmin.exe</b> can download arbitrary files &mdash; verify the job was not created by malicious software</div>");
        }

        // --- wscript.exe / cscript.exe ---
        if (procName == "wscript.exe" || procName == "cscript.exe")
        {
            steps.Add($"<div class='remediation-step'>Script execution at startup &mdash; review the .js/.vbs file content and check its digital signature</div>");
        }

        // --- msiexec.exe ---
        if (procName == "msiexec.exe")
        {
            steps.Add($"<div class='remediation-step'>MSI installer launched at startup &mdash; verify the .msi package is from a trusted publisher</div>");
        }

        // --- Generic next steps for any flagged event ---
        if (steps.Count == 0)
        {
            // No specific remediation found, give generic advice
            if (!string.IsNullOrEmpty(ev.LikelyTrigger))
            {
                steps.Add($"<div class='remediation-step'>Investigate autostart entry: <code>{HtmlEncode(ev.LikelyTrigger)}</code></div>");
            }
            steps.Add($"<div class='remediation-step'>Check if <b>{HtmlEncode(procName)}</b> is in <code>{HtmlEncode(c.Hashes ?? "no hash recorded")}</code> on VirusTotal</div>");
            steps.Add($"<div class='remediation-step'>Review the parent process chain for unexpected ancestors</div>");
        }

        // Always add the search tip for non-technical users
        var searchQuery = string.IsNullOrEmpty(c.CommandLine) ? "" : (c.CommandLine.Length > 60 ? c.CommandLine[..60] : c.CommandLine);
        steps.Add($"<div class='remediation-step'>Search online for: <code>{HtmlEncode(procName)} {HtmlEncode(searchQuery)}</code></div>");

        return string.Join("", steps);
    }

    private static string GenerateReportAIPrompt(
        List<MergedEvent> events,
        List<AutostartEntry> autostart,
        string machineName,
        string osVersion,
        string user,
        string reportTime,
        int flaggedCount,
        int benignCount,
        int unknownN)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("I need a comprehensive security analysis of this Windows system activity report from Inspector (a Sysmon monitoring tool). Please analyze the complete report and provide a summary in simple terms:");
        sb.AppendLine();
        sb.AppendLine("**REPORT OVERVIEW:**");
        sb.AppendLine($"- Machine: {machineName}");
        sb.AppendLine($"- OS: {osVersion}");
        sb.AppendLine($"- Report Time: {reportTime}");
        sb.AppendLine($"- Total Processes Captured: {events.Count}");
        sb.AppendLine($"- ⚠️ INVESTIGATE: {flaggedCount} (High risk - needs immediate attention)");
        sb.AppendLine($"- ❓ UNKNOWN: {unknownN} (Medium risk - requires investigation)");
        sb.AppendLine($"- ✅ BENIGN: {benignCount} (Low risk - normal/trusted)");
        sb.AppendLine($"- Autostart Entries Scanned: {autostart.Count}");
        sb.AppendLine();

        // Top suspicious events
        var suspiciousEvents = events
            .Where(e => e.RiskLevel == "investigate")
            .OrderByDescending(e => e.Create.TimeUtc)
            .Take(10)
            .ToList();

        if (suspiciousEvents.Any())
        {
            sb.AppendLine("**TOP SUSPICIOUS EVENTS (Need Immediate Attention):**");
            foreach (var ev in suspiciousEvents)
            {
                var c = ev.Create;
                sb.AppendLine($"- **{Path.GetFileName(c.Image)}** - Ran for {(ev.LifetimeMs.HasValue ? ev.LifetimeMs.Value.ToString("0") : "?")}ms");
                sb.AppendLine($"  Command: {TruncateString(c.CommandLine ?? "N/A", 100)}");
                sb.AppendLine($"  User: {c.User ?? "Unknown"}, Time: {c.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"  Publisher: {c.Company ?? "Unknown"}, Trigger: {ev.LikelyTrigger ?? "None detected"}");
                sb.AppendLine();
            }
        }

        // Process statistics
        var topProcesses = events
            .GroupBy(e => Path.GetFileName(e.Create.Image))
            .Select(g => new { Process = g.Key, Count = g.Count(), InvestigateCount = g.Count(e => e.RiskLevel == "investigate") })
            .OrderByDescending(p => p.Count)
            .Take(10)
            .ToList();

        sb.AppendLine("**PROCESS STATISTICS (Top 10 most active):**");
        foreach (var proc in topProcesses)
        {
            sb.AppendLine($"- {proc.Process}: {proc.Count} total, {proc.InvestigateCount} suspicious");
        }
        sb.AppendLine();

        // Time patterns
        var hourlyDistribution = events
            .GroupBy(e => e.Create.TimeUtc.ToLocalTime().Hour)
            .OrderByDescending(g => g.Count())
            .Take(5)
            .ToList();

        if (hourlyDistribution.Count > 0)
        {
            sb.AppendLine("**ACTIVITY PATTERNS (Busiest hours):**");
            foreach (var hour in hourlyDistribution)
            {
                sb.AppendLine($"- {hour.Key:00}:00-{hour.Key:00}:59: {hour.Count()} processes");
            }
            sb.AppendLine();
        }

        // User activity
        var userActivity = events
            .GroupBy(e => e.Create.User ?? "Unknown")
            .OrderByDescending(g => g.Count())
            .Take(5)
            .ToList();

        if (userActivity.Count > 0)
        {
            sb.AppendLine("**USER ACTIVITY (Top users):**");
            foreach (var userGrp in userActivity)
            {
                sb.AppendLine($"- {userGrp.Key}: {userGrp.Count()} processes");
            }
            sb.AppendLine();
        }

        // Suspicious autostart entries
        var suspiciousAutostart = autostart
            .Where(a => !a.KnownBenign)
            .Take(10)
            .ToList();

        if (suspiciousAutostart.Any())
        {
            sb.AppendLine("**SUSPICIOUS AUTOSTART ENTRIES (Check these):**");
            foreach (var entry in suspiciousAutostart)
            {
                sb.AppendLine($"- **{entry.Name}** ({entry.Source})");
                sb.AppendLine($"  Command: {TruncateString(entry.Command, 80)}");
                sb.AppendLine();
            }
        }

        sb.AppendLine("**ANALYSIS REQUESTED:**");
        sb.AppendLine("1. **OVERALL SYSTEM HEALTH**: Rate the overall security health (Excellent/Good/Concerning/Critical)");
        sb.AppendLine("2. **IMMEDIATE RISKS**: What are the most dangerous findings that need attention NOW?");
        sb.AppendLine("3. **LONG-TERM PATTERNS**: Are there suspicious patterns (time-based, user-based, process-based)?");
        sb.AppendLine("4. **RECOMMENDED ACTIONS**: Provide clear next steps with priorities:");
        sb.AppendLine("   a) Immediate actions (today)");
        sb.AppendLine("   b) Short-term actions (this week)");
        sb.AppendLine("   c) Long-term improvements");
        sb.AppendLine("5. **BENIGN ACTIVITY**: What normal activity should I NOT worry about?");
        sb.AppendLine("6. **FOR NON-TECHNICAL USERS**: Explain in simple terms what this means for my computer's safety.");
        sb.AppendLine();
        sb.AppendLine("Please provide a comprehensive yet easy-to-understand security summary suitable for both technical and non-technical users. Include specific, actionable recommendations.");

        return sb.ToString();
    }

    private static string TruncateString(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    private static string HtmlEncode(string? s) => HtmlEncoder.Default.Encode(s ?? "");
}
