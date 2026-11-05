using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.AccessControl;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SysmonChecker
{
    public enum CheckState { Ok, Warning, Error }

    public class CheckResult
    {
        public CheckState State = CheckState.Error;
        public string Headline = "";
        public string ExePath;
        public readonly List<string> Lines = new List<string>();
    }

    public class ProcessOutput
    {
        public int ExitCode;
        public bool TimedOut;
        public string Output = "";
    }

    /// <summary>Detection of Sysmon on Windows.</summary>
    public static class SystemChecks
    {
        const StringComparison OIC = StringComparison.OrdinalIgnoreCase;

        public static bool IsAdmin()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static CheckResult CheckSysmon(AppSettings s)
        {
            var r = new CheckResult();
            string svcName = FindSysmonServiceName();
            bool running = false;

            if (svcName != null)
            {
                using (var sc = new ServiceController(svcName))
                {
                    running = sc.Status == ServiceControllerStatus.Running;
                    r.Lines.Add($"Service:        {sc.ServiceName} – {StatusText(sc.Status)} (startup: {sc.StartType})");
                }
                r.ExePath = GetServiceBinary(svcName);
                if (r.ExePath != null)
                {
                    r.Lines.Add("Binary:         " + r.ExePath);
                    string ver = FileVersion(r.ExePath);
                    if (ver != null) r.Lines.Add("Version:        " + ver);
                }
            }
            else
            {
                r.Lines.Add("Service:        not found");
                r.Lines.Add(BuiltInSysmonExe() != null
                    ? "Built-in:       the Windows feature Sysmon is enabled, but the service is not installed yet (sysmon -i) – Settings > \"Install Sysmon service\""
                    : "Built-in:       the Windows feature Sysmon is not enabled (Windows 11 / Server 2025) – Settings > \"Install Sysmon service\" enables it");
            }

            try
            {
                var devices = ServiceController.GetDevices();
                var drv = devices.FirstOrDefault(d => d.ServiceName.StartsWith("SysmonDrv", OIC));
                r.Lines.Add(drv != null ? $"Driver:         {drv.ServiceName} – {StatusText(drv.Status)}" : "Driver:         SysmonDrv not found");
                foreach (var d in devices) d.Dispose();
            }
            catch (Exception ex) { r.Lines.Add("Driver:         " + ex.Message); }

            bool channelOk = false;
            try
            {
                using (var cfg = new EventLogConfiguration(SysmonReader.Channel))
                {
                    channelOk = cfg.IsEnabled;
                    r.Lines.Add($"Event log:      {SysmonReader.Channel} – {(cfg.IsEnabled ? "enabled" : "DISABLED")}, max. {cfg.MaximumSizeInBytes / 1048576} MB");
                }
                try
                {
                    var info = EventLogSession.GlobalSession.GetLogInformation(SysmonReader.Channel, PathType.LogName);
                    r.Lines.Add($"Records:        {info.RecordCount}");
                    if (info.LastWriteTime.HasValue) r.Lines.Add($"Last write:     {info.LastWriteTime.Value:yyyy-MM-dd HH:mm:ss}");
                }
                catch { }
            }
            catch (EventLogNotFoundException) { r.Lines.Add("Event log:      Sysmon channel does not exist"); }
            catch (UnauthorizedAccessException) { r.Lines.Add("Event log:      access denied (run as administrator or add the user to Event Log Readers – Settings)"); }
            catch (Exception ex) { r.Lines.Add("Event log:      " + ex.Message); }

            r.Lines.Add("");
            r.Lines.Add(DescribeFile("Configuration:  ", s.SysmonConfigPath));

            if (svcName == null)
            {
                r.State = CheckState.Error;
                r.Headline = BuiltInSysmonExe() != null ? "Sysmon is enabled in Windows, but its service is not installed" : "Sysmon is not installed";
            }
            else if (!running) { r.State = CheckState.Warning; r.Headline = "Sysmon is installed but not running"; }
            else if (!channelOk) { r.State = CheckState.Warning; r.Headline = "Sysmon is running but its event log is unavailable"; }
            else { r.State = CheckState.Ok; r.Headline = "Sysmon is enabled and running"; }
            return r;
        }

        /// <summary>
        /// Built-in Sysmon (optional Windows feature "Sysmon", Windows 11 / Server 2025): enabling the feature only adds
        /// sysmon.exe to System32 – the service and the driver are created by "sysmon -i". Null = the feature is not enabled.
        /// </summary>
        public static string BuiltInSysmonExe()
        {
            string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sysmon.exe");
            return File.Exists(p) ? p : null;
        }

        static DateTime lastFullSearch = DateTime.MinValue;
        static string renamedService;

        public static string FindSysmonServiceName()
        {
            var services = ServiceController.GetServices();
            try
            {
                var hit = services.FirstOrDefault(x => x.ServiceName.StartsWith("Sysmon", OIC));
                if (hit != null) return hit.ServiceName;

                // the search below reads the version info of every service binary – when it found nothing, it is not
                // repeated on every check (Sysmon is not installed), only after a few minutes
                if (DateTime.UtcNow - lastFullSearch < TimeSpan.FromMinutes(5)) return renamedService;
                lastFullSearch = DateTime.UtcNow;
                renamedService = null;

                // Renamed Sysmon – search by the description of the binary
                foreach (var sc in services)
                {
                    string bin = GetServiceBinary(sc.ServiceName);
                    if (bin == null) continue;
                    try
                    {
                        var fvi = FileVersionInfo.GetVersionInfo(bin);
                        if ((fvi.FileDescription ?? "").IndexOf("System activity monitor", OIC) >= 0) return renamedService = sc.ServiceName;
                    }
                    catch { }
                }
            }
            finally { foreach (var sc in services) sc.Dispose(); }
            return null;
        }

        static readonly SecurityIdentifier[] NonAdminSids =
        {
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),                 // Everyone
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),          // Users
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),     // Authenticated Users
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),           // INTERACTIVE
        };

        const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
            | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | FileSystemRights.DeleteSubdirectoriesAndFiles;
        const FileSystemRights AncestorRights = FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
            | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

        /// <summary>
        /// True if a standard user can change the file or its folder (replace the exe, edit the yaml): Everyone, Users,
        /// Authenticated Users, INTERACTIVE or – in an elevated process – the signed-in user's own account have write access.
        /// Such a file must not be run / loaded with administrator rights without the user knowing. Unknown = true.
        /// </summary>
        public static bool WritableByStandardUsers(string file)
        {
            try
            {
                var sids = NonAdminSids.ToList();
                var me = WindowsIdentity.GetCurrent().User;
                if (me != null) sids.Add(me);
                var rules = new List<AuthorizationRuleCollection>
                {
                    File.GetAccessControl(file).GetAccessRules(true, true, typeof(SecurityIdentifier)),
                    Directory.GetAccessControl(Path.GetDirectoryName(Path.GetFullPath(file))).GetAccessRules(true, true, typeof(SecurityIdentifier)),
                };
                bool Grants(AuthorizationRuleCollection coll, FileSystemRights rights)
                {
                    foreach (FileSystemAccessRule r in coll)
                        if (r.AccessControlType == AccessControlType.Allow && (r.FileSystemRights & rights) != 0
                            && (r.PropagationFlags & PropagationFlags.InheritOnly) == 0   // applies to children only, not to this object
                            && sids.Contains((SecurityIdentifier)r.IdentityReference))
                            return true;
                    return false;
                }
                // on the folder also "create files" counts: a DLL placed next to the exe is loaded by it
                if (rules.Any(c => Grants(c, WriteRights))) return true;
                // every folder above up to the root of the drive: whoever can delete / rename a subfolder there (or take
                // the folder over) can put a folder of his own in place of ours. "Create folders" alone (C:\ grants it to
                // all users) is not enough – the existing folder cannot be replaced without a delete right.
                for (var d = Directory.GetParent(Path.GetDirectoryName(Path.GetFullPath(file))); d != null; d = d.Parent)
                    if (Grants(Directory.GetAccessControl(d.FullName).GetAccessRules(true, true, typeof(SecurityIdentifier)), AncestorRights))
                        return true;
                return false;
            }
            catch { return true; }
        }


        /// <summary>Fills in the bundled Sysmon configuration (config\sysmon\sysmon*.xml) if no path is set
        /// or the set file does not exist (e.g. the folder was moved to another computer).</summary>
        public static void AutoDetect(AppSettings s)
        {
            if (!string.IsNullOrWhiteSpace(s.SysmonConfigPath) && File.Exists(s.SysmonConfigPath)) return;
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            foreach (var dir in new[] { Path.Combine(baseDir, "config", "sysmon"), baseDir })
            {
                try
                {
                    var local = Directory.Exists(dir)
                        ? Directory.GetFiles(dir, "sysmon*.xml").FirstOrDefault(f => !f.EndsWith(".settings.xml", StringComparison.OrdinalIgnoreCase))
                        : null;
                    if (local != null) { s.SysmonConfigPath = local; return; }
                }
                catch { }
            }
        }

        // ------------------------------------------------------------------ helpers

        public static string GetServiceBinary(string service)
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service))
                {
                    var raw = k?.GetValue("ImagePath") as string;
                    if (string.IsNullOrWhiteSpace(raw)) return null;
                    raw = Environment.ExpandEnvironmentVariables(raw.Trim());
                    string path;
                    if (raw.StartsWith("\""))
                    {
                        int end = raw.IndexOf('"', 1);
                        path = end > 0 ? raw.Substring(1, end - 1) : raw.Trim('"');
                    }
                    else
                    {
                        int exe = raw.IndexOf(".exe", OIC);
                        path = exe > 0 ? raw.Substring(0, exe + 4) : raw;
                    }
                    string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                    if (path.StartsWith(@"\??\")) path = path.Substring(4);
                    if (path.StartsWith(@"\SystemRoot\", OIC)) path = Path.Combine(win, path.Substring(12));
                    else if (path.StartsWith(@"system32\", OIC)) path = Path.Combine(win, path);
                    return File.Exists(path) ? path : null;
                }
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ Event Log Readers

        /// <summary>Built-in local group whose members may read the Sysmon log without administrator rights.</summary>
        public const string EventLogReadersSid = "S-1-5-32-573";

        /// <summary>Local (possibly translated) name of the group, e.g. "Event Log Readers" / "Čtenáři protokolu událostí".</summary>
        public static string EventLogReadersName()
        {
            try
            {
                string n = new SecurityIdentifier(EventLogReadersSid).Translate(typeof(NTAccount)).Value;
                int i = n.IndexOf('\\');
                return i >= 0 ? n.Substring(i + 1) : n;
            }
            catch { return "Event Log Readers"; }
        }

        /// <summary>
        /// User signed in to this Windows session (DOMAIN\user) – also when the application was elevated
        /// with the credentials of another (administrator) account.
        /// </summary>
        public static string SessionUser()
        {
            try
            {
                string user = WtsString(5 /* WTSUserName */), domain = WtsString(7 /* WTSDomainName */);
                if (!string.IsNullOrEmpty(user)) return string.IsNullOrEmpty(domain) ? user : domain + "\\" + user;
            }
            catch { }
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }

        /// <summary>true/false = the account is / is not a member of the group; null = could not be determined.</summary>
        public static bool? IsEventLogReader(string account)
        {
            try
            {
                var sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
                using (var ctx = new PrincipalContext(ContextType.Machine))
                using (var grp = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, EventLogReadersSid))
                {
                    if (grp == null) return null;
                    // direct members only – enough for accounts added by this application
                    foreach (var m in grp.GetMembers(false))
                        using (m) if (m.Sid == sid) return true;
                    return false;
                }
            }
            catch { return null; }
        }

        /// <summary>Does the token of this process already contain the group (the user signed in again after being added)?</summary>
        public static bool TokenHasEventLogReaders()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return id.Groups != null && id.Groups.Any(g => g.Value == EventLogReadersSid);
        }

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);

        static string WtsString(int infoClass)
        {
            if (!WTSQuerySessionInformation(IntPtr.Zero, -1 /* current session */, infoClass, out var buf, out _)) return null;
            try { return Marshal.PtrToStringUni(buf); }
            finally { WTSFreeMemory(buf); }
        }

        // ------------------------------------------------------------------ processes

        static readonly System.Text.Encoding OemEncoding = GetOemEncoding();

        static System.Text.Encoding GetOemEncoding()
        {
            try { return System.Text.Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
            catch { return System.Text.Encoding.Default; }
        }

        public static ProcessOutput RunProcess(string exe, string args, int timeoutMs)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.CurrentDirectory,
                // console tools (net.exe, sysmon) write in the OEM code page – otherwise diacritics are broken
                StandardOutputEncoding = OemEncoding,
                StandardErrorEncoding = OemEncoding
            };
            var res = new ProcessOutput();
            using (var p = Process.Start(psi))
            {
                var o = p.StandardOutput.ReadToEndAsync();
                var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutMs))
                {
                    res.TimedOut = true;
                    try { p.Kill(); } catch { }
                }
                else p.WaitForExit();
                Task.WaitAll(new Task[] { o, e }, 3000);
                res.ExitCode = res.TimedOut ? -1 : p.ExitCode;
                string err = e.IsCompleted ? e.Result : "";
                res.Output = (o.IsCompleted ? o.Result : "") + (err.Length > 0 ? Environment.NewLine + err : "");
                if (res.TimedOut) res.Output += Environment.NewLine + "[the process exceeded the time limit and was terminated]";
            }
            return res;
        }

        static string FileVersion(string path)
        {
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                return string.IsNullOrEmpty(v.FileVersion) ? null : v.FileVersion;
            }
            catch { return null; }
        }

        static string StatusText(ServiceControllerStatus st)
        {
            switch (st)
            {
                case ServiceControllerStatus.Running: return "running";
                case ServiceControllerStatus.Stopped: return "stopped";
                case ServiceControllerStatus.StartPending: return "starting";
                case ServiceControllerStatus.StopPending: return "stopping";
                case ServiceControllerStatus.Paused: return "paused";
                default: return st.ToString();
            }
        }

        static string DescribeFile(string label, string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return label + "(not set)";
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return label + path + "  – FILE DOES NOT EXIST";
                return $"{label}{path}  ({FormatSize(fi.Length)}, modified {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss})";
            }
            catch (Exception ex) { return label + path + "  – " + ex.Message; }
        }

        public static string FormatSize(long bytes)
        {
            if (bytes >= 1L << 30) return $"{bytes / (double)(1L << 30):0.0} GB";
            if (bytes >= 1L << 20) return $"{bytes / (double)(1L << 20):0.0} MB";
            if (bytes >= 1L << 10) return $"{bytes / 1024.0:0.0} kB";
            return bytes + " B";
        }
    }
}
