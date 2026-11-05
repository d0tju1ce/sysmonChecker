using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.IO;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml.Linq;

namespace SysmonChecker
{
    /// <summary>
    /// "Settings" page: settings of the application (saved per computer), changes of Sysmon on this computer
    /// and read access to the Sysmon log. Options that need administrator rights are greyed out for a standard user.
    /// </summary>
    partial class SettingsTab : UserControl
    {
        readonly AppSettings s;
        readonly StatusTab status;
        readonly bool admin = SystemChecks.IsAdmin();
        readonly string groupName = SystemChecks.EventLogReadersName();
        readonly Field txtSysCfg = new Field(400) { Anchor = AnchorStyles.Left | AnchorStyles.Right };
        readonly NumberField numMax = new NumberField(10, 100000, 100), numRefresh = new NumberField(2, 3600, 5);
        readonly NumberField numLog = new NumberField(2, 102400, 64);
        readonly Toggle chkAuto = new Toggle("Auto-refresh");
        readonly Field txtUser = new Field(260);
        readonly Label lblMember = new Label { AutoSize = true, Font = Theme.F(10f, Weight.SemiBold), Margin = new Padding(Ui.S(3), 0, 0, Ui.S(8)) };
        readonly ToolTip tips = new ToolTip { AutoPopDelay = 20000 };

        public event EventHandler SettingsSaved;

        public SettingsTab(AppSettings settings, StatusTab statusTab)
        {
            s = settings;
            status = statusTab;
            Dock = DockStyle.Fill;

            var root = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));   // cards as wide as the page, not as their content
            if (!admin) root.Controls.Add(AdminCard());
            root.Controls.Add(AppCard());
            root.Controls.Add(AiCard());
            root.Controls.Add(SysmonCard());
            root.Controls.Add(AccessCard());
            var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true }.Also(Theme.DarkScrollBars);
            scroll.Controls.Add(root);
            Controls.Add(scroll);
            // the cards never get wider than the window (otherwise the right part is cut off when the window is
            // made smaller); long texts wrap
            scroll.ClientSizeChanged += (o, e) => FitWidth(root, scroll.ClientSize.Width);
            FitWidth(root, scroll.ClientSize.Width);

            status.Checked += async (o, e) => await RefreshSystemStateAsync();
            LoadToUi();
        }

        // ------------------------------------------------------------------ layout

        static Card NewCard() => new Card { Dock = DockStyle.Fill, AutoSize = true };

        static TableLayoutPanel Grid(int columns)
        {
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = columns };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 1; i < columns; i++) t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            return t;
        }

        /// <summary>Labels that wrap with the window width (width = card width minus the given reserve).</summary>
        readonly List<(Label Label, int Reserve)> wrapLabels = new List<(Label, int)>();

        void FitWidth(Control root, int width)
        {
            if (width <= 0) return;
            root.MaximumSize = new Size(width - Ui.S(4), 0);   // small reserve for the right border of the cards
            foreach (var (label, reserve) in wrapLabels)
                label.MaximumSize = new Size(Math.Max(Ui.S(200), width - reserve), 0);
        }

        void Title(TableLayoutPanel t, string title, string note)
        {
            var l = new Label { Text = title, AutoSize = true, Font = Theme.F(12.5f, Weight.Bold), Margin = new Padding(0, 0, 0, Ui.S(2)) };
            var n = new Label { Text = note, AutoSize = true, ForeColor = Theme.SubText, Margin = new Padding(Ui.S(1), 0, 0, Ui.S(10)) };
            wrapLabels.Add((n, Ui.S(60)));
            t.Controls.Add(l); t.SetColumnSpan(l, t.ColumnCount);
            t.Controls.Add(n); t.SetColumnSpan(n, t.ColumnCount);
        }

        static void Row(TableLayoutPanel t, params Control[] controls)
        {
            var f = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, Ui.S(6)) };
            f.Controls.AddRange(controls);
            t.Controls.Add(f); t.SetColumnSpan(f, t.ColumnCount);
        }

        static Label FieldLabel(string text) =>
            new Label { Text = text, AutoSize = true, ForeColor = Theme.SubText, Font = Theme.F(9f, Weight.SemiBold), Margin = new Padding(Ui.S(3), 0, 0, Ui.S(2)) };

        /// <summary>Button that needs administrator rights – greyed out for a standard user.</summary>
        Button AdminButton(string text, Func<Task> action, string tip)
        {
            var b = Ui.B(text, async (o, e) => await action());
            b.Enabled = admin;
            tips.SetToolTip(b, tip + (admin ? "" : "\n\nRequires administrator rights – use \"Restart as administrator\"."));
            return b;
        }

        Control AdminCard()
        {
            var card = NewCard();
            var t = Grid(2);
            var l = new Label
            {
                Text = "Running as a standard user – the greyed-out options require administrator rights.",
                AutoSize = true, Font = Theme.F(10f, Weight.SemiBold), Anchor = AnchorStyles.Left, Margin = new Padding(Ui.S(3), 0, 0, 0)
            };
            wrapLabels.Add((l, Ui.S(320)));
            t.Controls.Add(l, 0, 0);
            t.Controls.Add(Ui.B("Restart as administrator", (o, e) => RestartElevated()), 1, 0);
            card.Controls.Add(t);
            return card;
        }

        Control AppCard()
        {
            var card = NewCard();
            var t = Grid(3);
            Title(t, "Application", "Saved to sysmonChecker.settings.xml next to the application, separately for this computer (" + AppSettings.Computer + ").");

            var cfg = FieldLabel("Sysmon configuration (XML)");
            t.Controls.Add(cfg); t.SetColumnSpan(cfg, 3);
            t.Controls.Add(txtSysCfg);
            t.Controls.Add(Ui.B("Browse", (o, e) => Browse()));
            t.Controls.Add(Ui.B("Open", (o, e) => OpenInEditor(txtSysCfg.Value)));

            var l1 = Ui.L("Max. events shown"); l1.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            var nums = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Fill, Margin = new Padding(0, Ui.S(6), 0, Ui.S(8)) };
            nums.Controls.AddRange(new Control[] { l1, numMax, Ui.L("Auto-refresh interval (s)"), numRefresh, chkAuto });
            tips.SetToolTip(chkAuto, "Reloads the events periodically (interval on the left) while the Events page is shown.");
            // takes effect immediately; saved with the other settings
            chkAuto.CheckedChanged += (o, e) => { if (loadingUi) return; ApplyFromUi(); SettingsSaved?.Invoke(this, EventArgs.Empty); };
            t.Controls.Add(nums); t.SetColumnSpan(nums, 3);

            var save = Ui.B("Save settings", async (o, e) => await SaveAsync(), ButtonKind.Primary);
            tips.SetToolTip(save, "Saves only the settings of this application (configuration path, max. events, auto-refresh)\nto sysmonChecker.settings.xml. Does not change Sysmon.");
            Row(t, save);

            card.Controls.Add(t);
            return card;
        }

        Control SysmonCard()
        {
            var card = NewCard();
            var t = Grid(1);
            Title(t, "Sysmon on this computer", "Changes the monitoring on this computer – not stored in the settings file and not copied with the application folder.");

            Row(t,
                AdminButton("Install Sysmon service", InstallSysmonAsync,
                    "Built-in Sysmon of Windows 11 / Server 2025: enables the Windows feature \"Sysmon\" if needed and installs the service\n" +
                    "and the driver with the configuration above (sysmon -i <xml>). Enabling the feature alone does not start Sysmon."),
                AdminButton("Apply configuration to Sysmon", ApplySysmonConfigAsync,
                    "Loads the configuration XML above into the running Sysmon (sysmon -c <xml>).\nFrom then on Sysmon records according to these rules, also after a restart."),
                AdminButton("Show active Sysmon configuration", ShowSysmonConfigAsync,
                    "Shows the rules the running Sysmon uses right now (sysmon -c).\n\"No rules installed\" = no configuration has been applied yet."));

            var l2 = Ui.L("Sysmon event log max. size (MB)"); l2.Margin = new Padding(Ui.S(3), Ui.S(10), Ui.S(4), 0);
            numLog.Box.Enabled = admin;
            Row(t, l2, numLog, AdminButton("Set log size", SetLogSizeAsync,
                "Changes the maximum size of the Microsoft-Windows-Sysmon/Operational log (Windows default 64 MB).\nWhen the log is full, the oldest events are overwritten."));

            card.Controls.Add(t);
            return card;
        }

        Control AccessCard()
        {
            var card = NewCard();
            var t = Grid(1);
            Title(t, "Access to the Sysmon log",
                "The Sysmon log can be read by administrators and by members of the local group \"" + groupName + "\".\n" +
                "A member can use sysmonChecker without administrator rights. The change takes effect after the user signs out and in again.");
            wrapLabels.Add((lblMember, Ui.S(60)));
            t.Controls.Add(lblMember);
            t.Controls.Add(FieldLabel("User (DOMAIN\\user or COMPUTER\\user)"));
            txtUser.Value = SystemChecks.SessionUser();
            txtUser.Box.KeyDown += async (o, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await RefreshMembershipAsync(); } };
            Row(t, txtUser,
                AdminButton("Add to " + groupName, AddToEventLogReadersAsync,
                    "Adds the user to the local group \"" + groupName + "\" (net localgroup … /add)."),
                Ui.B("Check membership", async (o, e) => await RefreshMembershipAsync()));
            card.Controls.Add(t);
            return card;
        }

        // ------------------------------------------------------------------ settings

        bool loadingUi, uiLoaded;

        public void LoadToUi()
        {
            loadingUi = true;   // the toggles fire CheckedChanged -> ApplyFromUi would read half-filled fields
            try
            {
                txtSysCfg.Value = s.SysmonConfigPath;
                numMax.Value = s.MaxEvents;
                numRefresh.Value = s.RefreshSeconds;
                chkAuto.Checked = s.AutoRefresh;
                LoadAiToUi();
            }
            finally { loadingUi = false; uiLoaded = true; }
        }

        public void ApplyFromUi()
        {
            if (!uiLoaded) return;   // the fields are still empty (start of the application)
            s.SysmonConfigPath = txtSysCfg.Value.Trim().Trim('"');
            s.MaxEvents = numMax.Value;
            s.RefreshSeconds = numRefresh.Value;
            s.AutoRefresh = chkAuto.Checked;
            ApplyAiFromUi();
        }

        async Task SaveAsync()
        {
            ApplyFromUi();
            try { s.Save(); }
            catch (Exception ex) { Ui.Warn(this, "The settings could not be saved:\n" + ex.Message); }
            SettingsSaved?.Invoke(this, EventArgs.Empty);
            await status.RunChecksAsync();
        }

        void Browse()
        {
            using (var dlg = new OpenFileDialog { Filter = "Sysmon configuration (*.xml)|*.xml|All files (*.*)|*.*", CheckFileExists = true })
            {
                try
                {
                    string cur = txtSysCfg.Value.Trim();
                    if (cur.Length > 0)
                    {
                        string dir = Directory.Exists(cur) ? cur : Path.GetDirectoryName(cur);
                        if (Directory.Exists(dir)) dlg.InitialDirectory = dir;
                        if (File.Exists(cur)) dlg.FileName = Path.GetFileName(cur);
                    }
                }
                catch { }
                if (dlg.ShowDialog(this) == DialogResult.OK) txtSysCfg.Value = dlg.FileName;
            }
        }

        void OpenInEditor(string path)
        {
            path = path.Trim().Trim('"');
            if (!File.Exists(path)) { Ui.Warn(this, "The file does not exist:\n" + path); return; }
            // full path – a notepad.exe in the current folder or in PATH must not be started (possibly elevated)
            try { Process.Start(Path.Combine(Environment.SystemDirectory, "notepad.exe"), "\"" + path + "\""); }
            catch (Exception ex) { Ui.Warn(this, "Notepad could not be started:\n" + ex.Message); }
        }

        /// <summary>Current log size and group membership – after every Sysmon check.</summary>
        async Task RefreshSystemStateAsync()
        {
            if (!numLog.Box.Focused)
            {
                long? size = await Task.Run(() => { try { using (var c = new EventLogConfiguration(SysmonReader.Channel)) return (long?)c.MaximumSizeInBytes; } catch { return null; } });
                if (size.HasValue) numLog.Value = (int)(size.Value / 1048576);
            }
            await RefreshMembershipAsync();
        }

        async Task RefreshMembershipAsync()
        {
            string user = txtUser.Value.Trim().Trim('"');
            if (user.Length == 0)
            {
                lblMember.Text = "Enter the user (DOMAIN\\user or COMPUTER\\user).";
                lblMember.ForeColor = Theme.SubText;
                return;
            }
            // visible feedback – the result is often the same as before
            lblMember.Text = "Checking membership of " + user + "…";
            lblMember.ForeColor = Theme.SubText;
            var minDelay = Task.Delay(300);
            bool? member = await Task.Run(() => SystemChecks.IsEventLogReader(user));
            await minDelay;
            bool self = string.Equals(user, SystemChecks.SessionUser(), StringComparison.OrdinalIgnoreCase);
            if (member == true)
            {
                bool effective = !self || admin || SystemChecks.TokenHasEventLogReaders();
                lblMember.Text = user + " is a member of \"" + groupName + "\"" + (effective ? "." : " – sign out and in again to apply it.");
                lblMember.ForeColor = effective ? Theme.Ok : Theme.Attention;
            }
            else if (member == false)
            {
                lblMember.Text = user + " is not a member of \"" + groupName + "\" – without administrator rights the Sysmon log cannot be read.";
                lblMember.ForeColor = Theme.Attention;
            }
            else
            {
                lblMember.Text = "The membership of " + user + " could not be determined (unknown account or domain not reachable).";
                lblMember.ForeColor = Theme.SubText;
            }
            lblMember.Text += "   (checked " + DateTime.Now.ToString("HH:mm:ss") + ")";
        }

        // ------------------------------------------------------------------ actions (administrator)

        async Task<bool> EnsureSysmonAsync()
        {
            if (status.SysmonExe == null) await status.RunChecksAsync();
            if (string.IsNullOrEmpty(status.SysmonExe) || !File.Exists(status.SysmonExe))
            {
                Ui.Warn(this, SystemChecks.BuiltInSysmonExe() != null
                    ? "The Windows feature Sysmon is enabled, but the Sysmon service is not installed yet – use \"Install Sysmon service\"."
                    : "Sysmon is not installed – use \"Install Sysmon service\" (built-in Sysmon of Windows 11 / Server 2025).");
                return false;
            }
            return true;
        }

        async Task ApplySysmonConfigAsync()
        {
            ApplyFromUi();
            string cfg = s.SysmonConfigPath;
            if (!File.Exists(cfg)) { Ui.Warn(this, "The Sysmon configuration file does not exist:\n" + cfg); return; }
            try { XDocument.Load(cfg); }
            catch (Exception ex) { Ui.Warn(this, "The file is not valid XML:\n" + ex.Message); return; }
            if (!await EnsureSysmonAsync()) return;
            string exe = status.SysmonExe;
            // what exactly is going to be loaded: a configuration that excludes everything would silently blind the detection
            var activeDump = await Task.Run(() => { try { return SystemChecks.RunProcess(exe, "-accepteula -c", 30000).Output; } catch { return ""; } });
            var report = SysmonConfigReport.Analyze(cfg, activeDump);
            if (MessageBox.Show(this, $"Apply the configuration to the running Sysmon ({exe})?\nThis changes the monitoring rules on this computer.\n\n" + report.Text,
                    Program.AppName, MessageBoxButtons.YesNo, report.Warnings > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                    report.Warnings > 0 ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1) != DialogResult.Yes) return;
            var r = await Task.Run(() => SystemChecks.RunProcess(exe, $"-accepteula -c \"{cfg}\"", 60000));
            Ui.ShowText(this, $"Sysmon -c  (exit code {r.ExitCode})", r.Output);
            await status.RunChecksAsync();
        }

        /// <summary>
        /// Built-in Sysmon: 1. enable the optional Windows feature "Sysmon" (DISM) when sysmon.exe is not in System32 yet,
        /// 2. install the service and the driver with the configuration of the application (sysmon -accepteula -i &lt;xml&gt;).
        /// Enabling the feature (Settings > Optional features, Enable-WindowsOptionalFeature) only adds the binary – without
        /// step 2 there is no Sysmon service, also after a restart.
        /// </summary>
        async Task InstallSysmonAsync()
        {
            string existing = await Task.Run(() => SystemChecks.FindSysmonServiceName());
            if (existing != null)
            {
                MessageBox.Show(this, $"Sysmon is already installed (service \"{existing}\"). Use \"Apply configuration to Sysmon\" to load the configuration.\n\n" +
                    "Built-in Sysmon cannot run next to the standalone Sysinternals Sysmon – to switch, uninstall the standalone one first (sysmon -u).",
                    Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            ApplyFromUi();
            string cfg = s.SysmonConfigPath;
            if (!File.Exists(cfg)) { Ui.Warn(this, "The Sysmon configuration file does not exist:\n" + cfg); return; }
            try { XDocument.Load(cfg); }
            catch (Exception ex) { Ui.Warn(this, "The file is not valid XML:\n" + ex.Message); return; }

            string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (SystemChecks.BuiltInSysmonExe() == null)
            {
                if (MessageBox.Show(this, "The Windows feature \"Sysmon\" is not enabled on this computer.\n\nEnable it now (DISM, can take a few minutes)?",
                        Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                Cursor = Cursors.WaitCursor;
                ProcessOutput d;
                try { d = await Task.Run(() => SystemChecks.RunProcess(Path.Combine(sys, "dism.exe"), "/Online /Enable-Feature /FeatureName:Sysmon /NoRestart /English", 900000)); }
                finally { Cursor = Cursors.Default; }
                if (d.ExitCode != 0 && d.ExitCode != 3010)
                {
                    Ui.ShowText(this, $"DISM – enabling Sysmon failed (exit code {d.ExitCode})",
                        (d.Output.IndexOf("Sysmon is unknown", StringComparison.OrdinalIgnoreCase) >= 0
                            ? "This Windows version has no built-in Sysmon (Windows 11 with the updates from February 2026 or newer, Windows Server 2025).\n" +
                              "Install the Windows updates, or use the standalone Sysmon from Sysinternals (docs\\Sysmon-Setup-Guide.md).\n\n" : "") + d.Output);
                    return;
                }
                if (SystemChecks.BuiltInSysmonExe() == null)
                {
                    Ui.ShowText(this, "DISM – restart needed",
                        "The feature was enabled, but sysmon.exe is not available yet – restart Windows and use \"Install Sysmon service\" again " +
                        "(enabling the feature does not install the service).\n\n" + d.Output);
                    return;
                }
            }
            string exe = SystemChecks.BuiltInSysmonExe();

            var report = SysmonConfigReport.Analyze(cfg, "");
            if (MessageBox.Show(this, $"Install the Sysmon service and driver ({exe}) with this configuration?\n" +
                    "Sysmon starts recording immediately and also after every restart.\n\n" + report.Text,
                    Program.AppName, MessageBoxButtons.YesNo, report.Warnings > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Question,
                    report.Warnings > 0 ? MessageBoxDefaultButton.Button2 : MessageBoxDefaultButton.Button1) != DialogResult.Yes) return;
            Cursor = Cursors.WaitCursor;
            ProcessOutput r;
            try { r = await Task.Run(() => SystemChecks.RunProcess(exe, $"-accepteula -i \"{cfg}\"", 180000)); }
            finally { Cursor = Cursors.Default; }
            await status.RunChecksAsync();
            string svc = await Task.Run(() => SystemChecks.FindSysmonServiceName());
            Ui.ShowText(this, $"sysmon -i  (exit code {r.ExitCode}) – " + (svc != null ? $"service \"{svc}\" installed" : "the service was NOT installed"), r.Output);
        }

        async Task ShowSysmonConfigAsync()
        {
            if (!await EnsureSysmonAsync()) return;
            string exe = status.SysmonExe;
            var r = await Task.Run(() => SystemChecks.RunProcess(exe, "-accepteula -c", 30000));
            string text = r.Output;
            if (text.IndexOf("No rules installed", StringComparison.OrdinalIgnoreCase) >= 0)
                text = "NOTE: \"No rules installed\" means that no configuration has been loaded into Sysmon yet.\n"
                     + "Sysmon then records only its default events (process create/terminate, driver load,\n"
                     + "file creation time changed, ...). Use \"Apply configuration to Sysmon\" to load config\\sysmon\\sysmonconfig.xml.\n\n" + text;
            Ui.ShowText(this, "Active Sysmon configuration", text);
        }

        async Task SetLogSizeAsync()
        {
            int mb = numLog.Value;
            if (MessageBox.Show(this, $"Set the maximum size of the log\n{SysmonReader.Channel}\nto {mb} MB?",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            try
            {
                await Task.Run(() =>
                {
                    using (var c = new EventLogConfiguration(SysmonReader.Channel))
                    {
                        c.MaximumSizeInBytes = (long)mb * 1048576;
                        c.SaveChanges();
                    }
                });
            }
            catch (UnauthorizedAccessException) { Ui.Warn(this, "Access denied – run " + Program.AppName + " as administrator."); return; }
            catch (Exception ex) { Ui.Warn(this, "The log size could not be changed:\n" + ex.Message); return; }
            await status.RunChecksAsync();
        }

        async Task AddToEventLogReadersAsync()
        {
            string user = txtUser.Value.Trim().Trim('"');
            if (user.Length == 0) { Ui.Warn(this, "Enter the user (DOMAIN\\user or COMPUTER\\user)."); return; }
            // the account must exist – its canonical name (resolved through the SID) is passed to net.exe, never the typed
            // text (quotes in it would add other accounts to the group)
            try
            {
                if (user.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0) throw new ArgumentException();
                var sid = (SecurityIdentifier)new NTAccount(user).Translate(typeof(SecurityIdentifier));
                user = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
            }
            catch { Ui.Warn(this, "The account \"" + txtUser.Value.Trim() + "\" was not found.\nEnter it as DOMAIN\\user or COMPUTER\\user."); return; }
            if (MessageBox.Show(this, $"Add the user\n{user}\nto the local group \"{groupName}\"?\n\nThe user will be able to read the Sysmon log (and other event logs) without administrator rights.",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            string net = Path.Combine(Environment.SystemDirectory, "net.exe");
            var r = await Task.Run(() => SystemChecks.RunProcess(net, $"localgroup \"{groupName}\" \"{user}\" /add", 30000));
            await RefreshMembershipAsync();
            if (r.ExitCode == 0)
                MessageBox.Show(this, $"{user} was added to \"{groupName}\".\nThe user has to sign out and in again for the change to take effect.",
                    Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            else if (r.Output.Contains("1378"))   // NERR: the account is already a member
                MessageBox.Show(this, $"{user} is already a member of \"{groupName}\".", Program.AppName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
                Ui.ShowText(this, $"net localgroup  (exit code {r.ExitCode})", r.Output);
        }

        void RestartElevated()
        {
            // an elevated process should not run from a folder a standard user (or malware running as the user) can change:
            // the exe, a DLL next to it or the configuration could be replaced before "Apply configuration"
            if (SystemChecks.WritableByStandardUsers(Application.ExecutablePath) && MessageBox.Show(this,
                    "The application folder can be changed without administrator rights:\n" + Path.GetDirectoryName(Application.ExecutablePath) +
                    "\n\nA program running as this user could replace the application, a DLL next to it or the Sysmon configuration " +
                    "before you use them with administrator rights. For administrator use, keep the application in a folder only " +
                    "administrators can change (e.g. C:\\Program Files\\sysmonChecker).\n\nRestart as administrator anyway?",
                    Program.AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { Verb = "runas", UseShellExecute = true });
                FindForm()?.Close();
            }
            catch (Win32Exception) { }   // UAC prompt cancelled
        }
    }
}
