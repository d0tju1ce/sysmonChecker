using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Xml.Linq;

namespace SysmonChecker
{
    public class SysmonEvent
    {
        public DateTime Time;
        public int EventId;
        public long RecordId;
        public string Computer = "";
        public readonly List<KeyValuePair<string, string>> Fields = new List<KeyValuePair<string, string>>();

        public string Get(string key)
        {
            foreach (var kv in Fields)
                if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) return kv.Value ?? "";
            return "";
        }

        string First(params string[] keys)
        {
            foreach (var k in keys)
            {
                var v = Get(k);
                if (v.Length > 0) return v;
            }
            return "";
        }

        public string TypeName => SysmonReader.GetName(EventId);
        public string Image => First("Image", "SourceImage");
        public string ProcessId => First("ProcessId", "SourceProcessId");
        public string User => First("User", "SourceUser");

        public string Summary
        {
            get
            {
                switch (EventId)
                {
                    case 1: return Join(Get("CommandLine"), Wrap("parent: ", Get("ParentImage")));
                    case 2: return Get("TargetFilename");
                    case 3:
                        return $"{Get("Protocol")} {Get("SourceIp")}:{Get("SourcePort")} → {Get("DestinationIp")}:{Get("DestinationPort")}"
                               + Wrap(" (", Get("DestinationHostname"), ")");
                    case 4: return Join(Get("State"), Get("Version"));
                    case 5: return "process terminated";
                    case 6: return Join(Get("ImageLoaded"), Wrap("signature: ", Get("Signature")));
                    case 7: return Join(Get("ImageLoaded"), Wrap("signature: ", Get("Signature")));
                    case 8: return $"→ {Get("TargetImage")} (StartAddress {Get("StartAddress")})";
                    case 9: return Get("Device");
                    case 10: return $"→ {Get("TargetImage")} (GrantedAccess {Get("GrantedAccess")})";
                    case 11: case 15: case 23: case 26: case 27: case 28: case 29:
                        return Get("TargetFilename");
                    case 12: case 13: case 14:
                        return Join(Get("EventType"), Get("TargetObject"), Wrap("= ", Get("Details")), Wrap("→ ", Get("NewName")));
                    case 16: return Get("Configuration");
                    case 17: case 18: return Get("PipeName");
                    case 19: case 20: case 21:
                        return Join(Get("Operation"), Get("Name"), Get("Query"), Get("Destination"), Get("Consumer"), Get("Filter"));
                    case 22: return Get("QueryName") + Wrap(" → ", Get("QueryResults"));
                    case 24: return Get("ClientInfo");
                    case 25: return Get("Type");
                    default:
                        return string.Join(" | ", Fields.Where(f => f.Key != "UtcTime" && f.Key != "RuleName" && !string.IsNullOrEmpty(f.Value)).Take(4).Select(f => f.Value));
                }
            }
        }

        static string Join(params string[] parts) => string.Join("  ", parts.Where(p => !string.IsNullOrEmpty(p)));
        static string Wrap(string prefix, string value, string suffix = "") => string.IsNullOrEmpty(value) || value == "-" ? "" : prefix + value + suffix;

        public bool ContainsText(string needle)
        {
            if (TypeName.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (Computer.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            foreach (var kv in Fields)
                if (kv.Value != null && kv.Value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }
    }

    public class SysmonQuery
    {
        public List<int> IncludeIds = new List<int>();
        public List<int> ExcludeIds = new List<int>();
        public DateTime? From, To;
        public string Text = "", Process = "", User = "";
        public int Max = 2000;
        public int ScanLimit = 200000;
    }

    public class SysmonResult
    {
        public List<SysmonEvent> Events = new List<SysmonEvent>();
        public int Scanned;
        public bool ScanLimitReached;
    }

    public static class SysmonReader
    {
        public const string Channel = "Microsoft-Windows-Sysmon/Operational";
        static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

        public static readonly SortedDictionary<int, string> EventNames = new SortedDictionary<int, string>
        {
            [1] = "Process Create",
            [2] = "File creation time changed",
            [3] = "Network connection",
            [4] = "Sysmon state changed",
            [5] = "Process terminated",
            [6] = "Driver loaded",
            [7] = "Image loaded",
            [8] = "CreateRemoteThread",
            [9] = "RawAccessRead",
            [10] = "ProcessAccess",
            [11] = "FileCreate",
            [12] = "Registry object create/delete",
            [13] = "Registry value set",
            [14] = "Registry object rename",
            [15] = "FileCreateStreamHash",
            [16] = "Sysmon config change",
            [17] = "Pipe created",
            [18] = "Pipe connected",
            [19] = "WMI EventFilter",
            [20] = "WMI EventConsumer",
            [21] = "WMI ConsumerToFilter",
            [22] = "DNS query",
            [23] = "FileDelete (archived)",
            [24] = "Clipboard change",
            [25] = "Process tampering",
            [26] = "FileDelete (logged)",
            [27] = "FileBlockExecutable",
            [28] = "FileBlockShredding",
            [29] = "FileExecutableDetected",
            [255] = "Sysmon error",
        };

        /// <summary>Short description of what each event type records (the "Event IDs" page).</summary>
        public static readonly Dictionary<int, string> EventDescriptions = new Dictionary<int, string>
        {
            [1] = "A process started – command line, hashes, parent process. The basis of most detections.",
            [2] = "A process changed a file's creation time – timestomping, used to hide dropped files.",
            [3] = "TCP/UDP connection made by a process – source/destination IP, port and host name.",
            [4] = "The Sysmon service started or stopped – an unexpected stop can mean tampering.",
            [5] = "A process ended – together with ID 1 gives the lifetime of a process.",
            [6] = "A kernel driver was loaded – signature and hashes; watch unsigned or vulnerable drivers.",
            [7] = "A DLL was loaded into a process – DLL side-loading and injection; high volume.",
            [8] = "A process created a thread in another process – a typical code injection technique.",
            [9] = "Direct read from a disk volume (\\\\.\\C:) bypassing the file system – e.g. copying NTDS.dit or SAM.",
            [10] = "A process opened another process (e.g. LSASS) – credential dumping, injection.",
            [11] = "A file was created or overwritten – dropped payloads, ransom notes, startup items.",
            [12] = "A registry key or value was created or deleted – persistence (Run keys, services).",
            [13] = "A registry value was set – persistence, disabling of security features.",
            [14] = "A registry key or value was renamed.",
            [15] = "An alternate data stream was created – Zone.Identifier of downloads, data hidden in ADS.",
            [16] = "The Sysmon configuration was changed (sysmon -c) – unexpected changes can mean tampering.",
            [17] = "A named pipe was created – used by C2 frameworks and PsExec for lateral movement.",
            [18] = "A process connected to a named pipe.",
            [19] = "A WMI event filter was registered – first part of WMI persistence.",
            [20] = "A WMI event consumer was registered (runs a command or script) – WMI persistence.",
            [21] = "A WMI consumer was bound to a filter – completes WMI persistence.",
            [22] = "DNS query made by a process – queried name and result; C2 domains, DNS tunnelling.",
            [23] = "A file was deleted and a copy archived – ransomware, wipers, attackers removing tools.",
            [24] = "The clipboard content changed.",
            [25] = "A process image was changed in memory – process hollowing or herpaderping.",
            [26] = "A file was deleted (logged only, no archived copy).",
            [27] = "Sysmon blocked the creation of an executable file (per the configuration).",
            [28] = "Sysmon blocked file shredding / wiping (e.g. SDelete).",
            [29] = "An executable (PE) file was created – detected by its header, not by the extension.",
            [255] = "Internal Sysmon error, e.g. under heavy load or a driver problem.",
        };

        public static string GetName(int id) => EventNames.TryGetValue(id, out var n) ? n : "Event " + id;

        public static string BuildXPath(SysmonQuery q)
        {
            var c = new List<string>();
            // consecutive IDs as ranges (1-29 = two comparisons instead of 29); the event log rejects a query with too
            // many expressions as invalid – above the limit the IDs are filtered here instead (Matches)
            var inc = Ranges(q.IncludeIds);
            var exc = Ranges(q.ExcludeIds);
            if (inc.Sum(r => r.Item1 == r.Item2 ? 1 : 2) + exc.Sum(r => r.Item1 == r.Item2 ? 1 : 2) <= MaxIdComparisons)
            {
                if (inc.Count > 0)
                    c.Add("(" + string.Join(" or ", inc.Select(r => r.Item1 == r.Item2 ? "EventID=" + r.Item1 : $"(EventID>={r.Item1} and EventID<={r.Item2})")) + ")");
                foreach (var r in exc)
                    c.Add(r.Item1 == r.Item2 ? "EventID!=" + r.Item1 : $"(EventID<{r.Item1} or EventID>{r.Item2})");
            }
            if (q.From.HasValue) c.Add($"TimeCreated[@SystemTime>='{Utc(q.From.Value)}']");
            if (q.To.HasValue) c.Add($"TimeCreated[@SystemTime<='{Utc(q.To.Value)}']");
            return c.Count == 0 ? "*" : "*[System[" + string.Join(" and ", c) + "]]";
        }

        const int MaxIdComparisons = 16;

        static List<Tuple<int, int>> Ranges(IEnumerable<int> ids)
        {
            var list = new List<Tuple<int, int>>();
            foreach (int id in ids.Distinct().OrderBy(i => i))
            {
                if (list.Count > 0 && list[list.Count - 1].Item2 == id - 1) list[list.Count - 1] = Tuple.Create(list[list.Count - 1].Item1, id);
                else list.Add(Tuple.Create(id, id));
            }
            return list;
        }

        static string Utc(DateTime t) => t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

        public static SysmonResult Read(SysmonQuery q, CancellationToken ct)
        {
            var res = new SysmonResult();
            var query = new EventLogQuery(Channel, PathType.LogName, BuildXPath(q)) { ReverseDirection = true };
            try
            {
                using (var reader = new EventLogReader(query))
                {
                    reader.BatchSize = 256;
                    EventRecord rec;
                    while (!ct.IsCancellationRequested && res.Events.Count < q.Max && (rec = reader.ReadEvent()) != null)
                    {
                        using (rec)
                        {
                            res.Scanned++;
                            var ev = Parse(rec);
                            if (Matches(ev, q)) res.Events.Add(ev);
                        }
                        if (res.Scanned >= q.ScanLimit) { res.ScanLimitReached = true; break; }
                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                throw new InvalidOperationException("Channel '" + Channel + "' does not exist – Sysmon is probably not installed.");
            }
            catch (UnauthorizedAccessException)
            {
                throw new InvalidOperationException("Access to the Sysmon log was denied – run sysmonChecker as administrator, or add the user to the Event Log Readers group (Settings page).");
            }
            return res;
        }

        static SysmonEvent Parse(EventRecord rec)
        {
            var ev = new SysmonEvent
            {
                EventId = rec.Id,
                RecordId = rec.RecordId ?? 0,
                Time = rec.TimeCreated ?? DateTime.MinValue,
                Computer = rec.MachineName ?? ""
            };
            try
            {
                var x = XElement.Parse(rec.ToXml());
                var data = x.Element(Ns + "EventData");
                if (data != null)
                    foreach (var d in data.Elements(Ns + "Data"))
                        ev.Fields.Add(new KeyValuePair<string, string>((string)d.Attribute("Name") ?? "", d.Value));
            }
            catch
            {
                int i = 0;
                foreach (var p in rec.Properties)
                    ev.Fields.Add(new KeyValuePair<string, string>("Field" + i++, p.Value?.ToString() ?? ""));
            }
            return ev;
        }

        static bool Matches(SysmonEvent ev, SysmonQuery q)
        {
            // also in the XPath query, unless there were too many IDs for it
            if (q.IncludeIds.Count > 0 && !q.IncludeIds.Contains(ev.EventId)) return false;
            if (q.ExcludeIds.Contains(ev.EventId)) return false;
            if (q.Process.Length > 0)
            {
                bool hit = false;
                foreach (var key in new[] { "Image", "SourceImage", "TargetImage", "ParentImage" })
                    if (ev.Get(key).IndexOf(q.Process, StringComparison.OrdinalIgnoreCase) >= 0) { hit = true; break; }
                if (!hit) return false;
            }
            if (q.User.Length > 0 && ev.User.IndexOf(q.User, StringComparison.OrdinalIgnoreCase) < 0 && ev.Get("TargetUser").IndexOf(q.User, StringComparison.OrdinalIgnoreCase) < 0)
                return false;
            if (q.Text.Length > 0)
            {
                bool negate = q.Text.StartsWith("!");
                string needle = negate ? q.Text.Substring(1) : q.Text;
                if (needle.Length > 0 && ev.ContainsText(needle) == negate) return false;
            }
            return true;
        }
    }
}
