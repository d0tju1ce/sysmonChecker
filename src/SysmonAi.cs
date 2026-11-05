using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SysmonChecker
{
    /// <summary>
    /// Sysmon events for the AI analyzer: identical events (same ID, process and detail) are grouped with a count,
    /// GUIDs and other noise are left out, long values are shortened. If there are more groups than the limit,
    /// the suspicious event IDs and the newest events are kept. The groups are sent oldest first (timeline).
    /// </summary>
    static class SysmonAi
    {
        const int MaxValue = 1200, MaxChars = 180000;

        static readonly HashSet<string> Skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "UtcTime", "ProcessGuid", "ParentProcessGuid", "SourceProcessGuid", "SourceProcessGUID", "TargetProcessGuid", "TargetProcessGUID",
            "LogonGuid", "LogonId", "TerminalSessionId", "FileVersion", "Product", "SourceThreadId", "SequenceNumber"
        };
        static readonly HashSet<string> UserFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "User", "SourceUser", "TargetUser", "ParentUser" };
        // host name of a connection (ID 3) → its IP field: the name of a computer in the local network is masked
        static readonly Dictionary<string, string> HostFields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            { ["SourceHostname"] = "SourceIp", ["DestinationHostname"] = "DestinationIp" };

        public static AiSource Source(List<SysmonEvent> shown, List<SysmonEvent> selected, string filters)
        {
            var src = new AiSource
            {
                Product = "Sysmon event log (Microsoft-Windows-Sysmon/Operational)",
                Filters = filters,
                TuningHint = "suggested Sysmon configuration changes (include/exclude rules in sysmonconfig.xml)",
                ApplyVerdicts = null,   // no false positive knowledge base in sysmonChecker (suricataChecker has one)
                Tasks = new[]
                {
                    ("Triage – find threats and suspicious activity",
                     "Triage these Sysmon events: identify malicious or suspicious activity (execution, persistence, credential access, " +
                     "defence evasion, lateral movement, command and control), rate the overall severity and list what needs attention first."),
                    ("Explain what happened (timeline)",
                     "Reconstruct what happened as a timeline: group related events (process trees by parent / child process, the network " +
                     "connections, DNS queries, file and registry changes of these processes) and explain them in plain language. Point out anything unusual."),
                    ("Find false positives and suggest tuning",
                     "Identify events that are most likely benign (Windows, security product, update and management activity) and propose " +
                     "concrete Sysmon exclusions for sysmonconfig.xml – always with full paths, never the bare file name – that reduce noise " +
                     "without losing the detection of real attacks."),
                    ("Answer my question only",
                     "Answer the analyst's question below using the events."),
                }
            };
            if (selected.Count > 0)
                src.Scopes.Add(Scope(selected.Count == 1 ? "Selected event" : "Selected rows", selected));
            src.Scopes.Add(Scope("All shown events", shown));
            var suspicious = shown.Where(e => SysmonTab.Suspicious.Contains(e.EventId)).ToList();
            if (suspicious.Count > 0) src.Scopes.Add(Scope("Suspicious event IDs only", suspicious));
            src.DefaultScope = selected.Count > 1 ? 0 : selected.Count == 1 ? 1 : 0;
            return src;
        }

        static AiScope Scope(string name, List<SysmonEvent> list) =>
            new AiScope { Name = name, Count = list.Count, Build = (r, max) => Build(list, r, max) };

        class Group
        {
            public SysmonEvent First;       // newest occurrence (the list is newest first)
            public DateTime Oldest, Newest;
            public int Count;
        }

        static AiPayload Build(List<SysmonEvent> list, Redactor r, int maxGroups)
        {
            var groups = new Dictionary<string, Group>();
            var order = new List<Group>();
            foreach (var e in list)
            {
                string key = e.EventId + "|" + e.Image + "|" + e.Summary + "|" + e.User;
                if (!groups.TryGetValue(key, out var g))
                {
                    g = new Group { First = e, Oldest = e.Time, Newest = e.Time };
                    groups[key] = g;
                    order.Add(g);
                }
                g.Count++;
                if (e.Time < g.Oldest) g.Oldest = e.Time;
                if (e.Time > g.Newest) g.Newest = e.Time;
            }

            // over the limit: the strongest signal first (process access after it), then the newest
            var chosen = order.Count <= maxGroups ? order
                : order.OrderBy(g => SysmonTab.Priority(g.First.EventId)).ThenByDescending(g => g.Newest).Take(maxGroups).ToList();

            var p = new AiPayload();
            var sb = new StringBuilder();
            sb.AppendLine("Counts by event ID in this selection: " + string.Join(", ",
                list.GroupBy(e => e.EventId).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {SysmonReader.GetName(g.Key)}: {g.Count()}")));
            if (list.Count > 0) sb.AppendLine($"Time span: {list.Min(e => e.Time):yyyy-MM-dd HH:mm:ss} – {list.Max(e => e.Time):yyyy-MM-dd HH:mm:ss} (local time)");
            sb.AppendLine();

            int n = 0;
            foreach (var g in chosen.OrderBy(g => g.Oldest))
            {
                var e = g.First;
                var block = new StringBuilder();
                block.Append($"[#{++n}] {g.Oldest:yyyy-MM-dd HH:mm:ss} | ID {e.EventId} {e.TypeName}");
                if (g.Count > 1) block.Append($" | ×{g.Count}, last {g.Newest:yyyy-MM-dd HH:mm:ss}");
                block.AppendLine();
                foreach (var f in e.Fields)
                {
                    if (Skip.Contains(f.Key) || string.IsNullOrWhiteSpace(f.Value) || f.Value == "-") continue;
                    string v = UserFields.Contains(f.Key) ? r.MaskUser(f.Value)
                        : HostFields.TryGetValue(f.Key, out var ipField) && Redactor.IsInternalAddress(e.Get(ipField)) ? r.MaskHost(f.Value)
                        : r.Mask(f.Value);
                    v = v.Replace("\r", " ").Replace("\n", " ");
                    if (v.Length > MaxValue) v = v.Substring(0, MaxValue) + "…(shortened)";
                    block.AppendLine($"  {f.Key}: {v}");
                }
                if (sb.Length + block.Length > MaxChars) { p.OmittedGroups += chosen.Count - n + 1; n--; break; }
                sb.Append(block);
                p.Events += g.Count;
            }
            p.Groups = n;
            p.OmittedGroups += order.Count - chosen.Count;
            p.Text = sb.ToString();
            return p;
        }
    }
}
