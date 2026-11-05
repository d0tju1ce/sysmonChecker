using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SysmonChecker
{
    /// <summary>
    /// What a Sysmon configuration file is going to change – shown before "Apply configuration to Sysmon". A replaced file
    /// that excludes (almost) everything would silently blind the detection, so the report lists: SHA256, the number of
    /// rules, event types that are switched off, exclusions that hide too much (a bare file name, a user-writable
    /// folder, a whole drive), write access for standard users and the hash of the configuration Sysmon uses now.
    /// </summary>
    class SysmonConfigReport
    {
        public string Text = "";
        public int Warnings;

        static readonly string[] ImageFields = { "Image", "ParentImage", "SourceImage", "TargetImage" };
        // folders a standard user can write to – an exclusion on them hides whatever malware puts there
        static readonly string[] UserWritable = { @"\temp\", @"\tmp\", @"\appdata\", @"\users\", @"\programdata\", @"\downloads\", @"\desktop\", @"\public\" };
        // event types a configuration may legitimately leave empty (they archive / block / capture private data)
        static readonly HashSet<string> OptionalTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "FileDelete", "ClipboardChange", "FileBlockExecutable", "FileBlockShredding" };

        public static SysmonConfigReport Analyze(string path, string activeDump)
        {
            var r = new SysmonConfigReport();
            var sb = new StringBuilder();
            string hash;
            using (var sha = SHA256.Create())
            using (var fs = File.OpenRead(path))
                hash = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
            sb.AppendLine("File:     " + path);
            sb.AppendLine("SHA256:   " + hash);

            var doc = XDocument.Load(path);
            var filters = doc.Descendants().Where(e => e.Attribute("onmatch") != null).ToList();
            int rules = doc.Descendants().Count(e => e.Attribute("condition") != null);
            int excludes = filters.Where(f => (string)f.Attribute("onmatch") == "exclude").SelectMany(f => f.Descendants()).Count(e => e.Attribute("condition") != null);
            sb.AppendLine($"Rules:    {rules} conditions, {excludes} of them exceptions (exclude)");

            // event types that are not recorded at all: an empty include filter (and no exclude filter for the same type)
            var types = filters.GroupBy(f => f.Name.LocalName);
            var off = types.Where(g => g.All(f => (string)f.Attribute("onmatch") == "include" && !f.HasElements)).Select(g => g.Key).ToList();
            var offImportant = off.Where(t => !OptionalTypes.Contains(t)).ToList();
            if (off.Count > 0) sb.AppendLine("Not recorded: " + string.Join(", ", off));
            if (offImportant.Count > 0)
            {
                r.Warnings++;
                sb.AppendLine("WARNING – these event types are switched off completely: " + string.Join(", ", offImportant));
            }

            // exclusions that hide too much – only direct conditions (a <Rule groupRelation="and"> combination is narrow)
            var broad = new List<string>();
            foreach (var f in filters.Where(f => (string)f.Attribute("onmatch") == "exclude"))
                foreach (var c in f.Elements().Where(e => e.Attribute("condition") != null))
                {
                    string field = c.Name.LocalName, cond = ((string)c.Attribute("condition") ?? "").ToLowerInvariant(), v = (c.Value ?? "").Trim();
                    string lv = v.ToLowerInvariant();
                    string why = null;
                    if (cond == "image") why = "file name only – any program with this name anywhere";
                    else if (cond == "end with" && ImageFields.Contains(field) && Regex.IsMatch(v, @"^\\?[^\\]+$")) why = "file name only – any folder";
                    else if (cond == "contains" && v.Length < 6) why = "very short text";
                    else if (ImageFields.Concat(new[] { "TargetFilename", "ImageLoaded" }).Contains(field)
                             && ((cond == "contains" && UserWritable.Any(u => lv.Contains(u)))
                                 // "begin with" a folder that is itself user-writable (C:\Users\, …\Temp\), not a protected subfolder of it
                                 || (cond == "begin with" && (UserWritable.Any(u => lv.EndsWith(u)) || Regex.IsMatch(lv, @"^[a-z]:\\users\\[^\\]*\\?$")))))
                        why = "a folder standard users can write to";
                    else if (cond == "begin with" && Regex.IsMatch(v, @"^[A-Za-z]:\\?$|^\\$")) why = "a whole drive";
                    else if ((cond == "is not" || cond == "excludes" || cond == "excludes any" || cond == "excludes all")) why = "negated condition – excludes everything else";
                    if (why != null) broad.Add($"  {f.Name.LocalName}: {field} {cond} \"{v}\" – {why}");
                }
            if (broad.Count > 0)
            {
                r.Warnings++;
                sb.AppendLine($"WARNING – {broad.Count} exception(s) may hide malicious activity:");
                foreach (var b in broad.Take(10)) sb.AppendLine(b);
                if (broad.Count > 10) sb.AppendLine($"  … and {broad.Count - 10} more");
            }

            if (SystemChecks.WritableByStandardUsers(path))
            {
                r.Warnings++;
                sb.AppendLine("WARNING – the file or its folder can be changed without administrator rights: check that it is the file you expect.");
            }

            // the configuration Sysmon uses now (sysmon -c prints its hash)
            var m = Regex.Match(activeDump ?? "", @"Config(?:uration)? hash:\s*(?:SHA256=)?([0-9A-Fa-f]{64})", RegexOptions.IgnoreCase);
            if (m.Success)
                sb.AppendLine(string.Equals(m.Groups[1].Value, hash, StringComparison.OrdinalIgnoreCase)
                    ? "Active:   the same file is already loaded in Sysmon."
                    : "Active:   a different configuration is loaded now (SHA256 " + m.Groups[1].Value.ToUpperInvariant() + ").");
            else if ((activeDump ?? "").IndexOf("No rules installed", StringComparison.OrdinalIgnoreCase) >= 0)
                sb.AppendLine("Active:   Sysmon has no configuration loaded yet.");

            r.Text = sb.ToString().TrimEnd();
            return r;
        }
    }
}
