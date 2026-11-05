using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SysmonChecker
{
    /// <summary>"Events" tab: reads and filters the Microsoft-Windows-Sysmon/Operational log.</summary>
    class SysmonTab : UserControl, ILazyTab
    {
        // few events, strong signal: 4 Sysmon service stopped / 16 configuration changed (tampering), 6 driver loaded (not
        // signed by Microsoft – the configuration excludes those), 8 remote thread, 10 process access (LSASS), 19–21 WMI
        // persistence, 25 process tampering, 27–29 blocked / new executables, 255 Sysmon error
        public static readonly HashSet<int> Suspicious = new HashSet<int> { 4, 6, 8, 10, 16, 19, 20, 21, 25, 27, 28, 29, 255 };

        /// <summary>Order for the AI payload above the group limit: 0 = strongest signal, 1 = process access (can be
        /// frequent – must not push the rest out), 2 = the other events.</summary>
        public static int Priority(int id) => id == 10 ? 1 : Suspicious.Contains(id) ? 0 : 2;

        readonly AppSettings s;
        readonly DarkCombo cboId = new DarkCombo(250, editable: true);
        readonly TimeRangeSelector time = new TimeRangeSelector(2);
        readonly Field txtProc = new Field(150), txtUser = new Field(120), txtText = new Field(190);
        readonly NumberField numMax = new NumberField(10, 100000, 100, 75);
        readonly Button btnLoad;
        readonly DataGridView grid = Ui.CreateGrid();
        readonly EventDetailView txtDetail = new EventDetailView();
        readonly SplitContainer split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = Theme.Bg, SplitterWidth = Ui.S(12) };
        readonly Label lblStatus = new Label { Dock = DockStyle.Bottom, Height = Ui.S(28), TextAlign = ContentAlignment.BottomLeft, ForeColor = Theme.SubText };
        readonly DataTable table = new DataTable();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Card filters = new Card { Dock = DockStyle.Top, Padding = new Padding(Ui.S(10), Ui.S(8), Ui.S(10), Ui.S(8)) };
        readonly TableLayoutPanel filterGrid = new TableLayoutPanel { Dock = DockStyle.Top, Margin = new Padding(0) };
        readonly List<Label> filterLabels = new List<Label>();
        readonly (string Label, Control Control)[] filterFields;
        readonly FlowLayoutPanel filterActions;
        int filterPairs;
        List<SysmonEvent> events = new List<SysmonEvent>();
        CancellationTokenSource cts;
        bool loading, loadedOnce, restartPending;

        /// <summary>Open the "Event IDs" page at this ID (0 = no particular ID).</summary>
        public event Action<int> DescribeIdRequested;

        public SysmonTab(AppSettings settings)
        {
            s = settings;
            Dock = DockStyle.Fill;

            cboId.Items.Add("All");
            foreach (var kv in SysmonReader.EventNames) cboId.Items.Add($"{kv.Key} - {kv.Value}");
            cboId.SelectedIndex = 0;

            btnLoad = Ui.B("Load", async (o, e) => await LoadAsync(false), ButtonKind.Primary);
            // applies the Event ID filter right away (the description of an ID: right click / double click on the ID in the table)
            var btnFilter = Ui.B("Filter", async (o, e) => await ReloadAsync());
            var tip = new ToolTip();
            tip.SetToolTip(btnFilter, "Shows the events of the selected / typed event IDs (e.g. 1,3,22 or !7).");
            tip.SetToolTip(cboId,"Select an event type, or type several IDs separated by commas (e.g. 1,3,22).\nExclude an ID: !7");
            tip.SetToolTip(txtProc.Box, "Part of the process path/name (Image, ParentImage, SourceImage, TargetImage)");
            tip.SetToolTip(txtUser.Box, "Part of the user name, e.g. SYSTEM or DOMAIN\\john");
            tip.SetToolTip(txtText.Box, "Full-text search in all event fields. Prefix ! = exclude events containing the text.");

            // Event ID box + Filter button share one grid cell
            var idCell = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, Height = Ui.S(38), Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0) };
            idCell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            idCell.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            cboId.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            idCell.Controls.Add(cboId, 0, 0);
            idCell.Controls.Add(btnFilter, 1, 0);

            filterFields = new[]
            {
                ("Event ID", (Control)idCell), ("Time", time.Preset), ("From", time.From), ("To", time.To),
                ("Process", txtProc), ("User", txtUser), ("Text", txtText), ("Max. events", numMax)
            };
            foreach (var (label, ctl) in filterFields)
            {
                filterLabels.Add(new Label { Text = label, AutoSize = true, ForeColor = Theme.SubText, Anchor = AnchorStyles.Left, Margin = new Padding(Ui.S(4), 0, Ui.S(8), 0) });
                if (ctl != numMax) ctl.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            }
            filterActions = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, Ui.S(4), 0, 0) };
            filterActions.Controls.AddRange(new Control[]
            {
                btnLoad,
                Ui.B("Clear filters", (o, e) => ClearFilters()),
                Ui.B("Export CSV", (o, e) => Ui.ExportCsv(this, grid, "sysmon")),
                Ui.B("AI analyzer", (o, e) => OpenAiAnalyzer())
            });
            // layout and height follow the width of the card (computed – AutoSize does not grow the card reliably)
            filters.SizeChanged += (o, e) => ArrangeFilters();
            ArrangeFilters();
            foreach (Control c in new Control[] { cboId, txtProc.Box, txtUser.Box, txtText.Box })
                c.KeyDown += async (o, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; await ReloadAsync(); } };

            table.Columns.Add("_idx", typeof(int));
            Ui.AddColumn(grid, table, "Time", "Time", typeof(DateTime), 150, format: Ui.DateFormatMs);
            Ui.AddColumn(grid, table, "ID", "ID", typeof(int), 45);
            Ui.AddColumn(grid, table, "Type", "Event type", typeof(string), 160);
            Ui.AddColumn(grid, table, "Process", "Process", typeof(string), 260);
            Ui.AddColumn(grid, table, "PID", "PID", typeof(string), 60);
            Ui.AddColumn(grid, table, "User", "User", typeof(string), 160);
            Ui.AddColumn(grid, table, "Detail", "Detail", typeof(string), 400, fill: true);
            Ui.AddColumn(grid, table, "RecordId", "Record ID", typeof(long), 95);
            grid.DataSource = table;
            grid.SelectionChanged += (o, e) => ShowDetail();
            grid.CellFormatting += Grid_CellFormatting;
            var menu = Ui.AttachCellMenu(grid, async v => { txtText.Value = v; await ReloadAsync(); });
            int menuId = 0;
            grid.CellMouseDown += (o, e) =>
            {
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && grid.Rows[e.RowIndex].DataBoundItem is DataRowView rv) menuId = (int)rv["ID"];
            };
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Show only this event ID", null, async (o, e) => await ShowIdsAsync(new List<int> { menuId }));
            menu.Items.Add("Hide this event ID", null, async (o, e) => await ShowIdsAsync(new List<int> { -menuId }));
            menu.Items.Add("What is this event ID?", null, (o, e) => DescribeIdRequested?.Invoke(menuId));
            // double-click on the ID or event type -> description of the event type
            grid.CellDoubleClick += (o, e) =>
            {
                if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
                string col = grid.Columns[e.ColumnIndex].Name;
                if ((col == "ID" || col == "Type") && grid.Rows[e.RowIndex].DataBoundItem is DataRowView rv) DescribeIdRequested?.Invoke((int)rv["ID"]);
            };

            filters.Controls.Add(filterGrid);
            // the card follows the height of the filter grid (2 or 4 field pairs per row)

            var detailCard = new Card { Dock = DockStyle.Fill, Margin = new Padding(0) };
            detailCard.Controls.Add(txtDetail);
            split.Panel1.Controls.Add(grid);
            split.Panel2.Controls.Add(detailCard);
            split.FixedPanel = FixedPanel.Panel2;
            var gap = new Panel { Dock = DockStyle.Top, Height = Ui.S(10) };

            Controls.Add(split);
            Controls.Add(gap);
            Controls.Add(filters);
            Controls.Add(lblStatus);

            // initial detail panel height, once the page has its real size
            bool splitSet = false;
            split.SizeChanged += (o, e) =>
            {
                if (splitSet || split.Height < Ui.S(400)) return;
                try { split.SplitterDistance = split.Height - Ui.S(240); splitSet = true; } catch { }
            };
            // auto-refresh (on/off and interval) is set on the Settings page; it runs while this page is shown
            timer.Tick += async (o, e) =>
            {
                if (!s.AutoRefresh || loading || !Visible) return;
                // several rows selected (e.g. for the AI analyzer): a refresh would rebuild the table and lose the selection
                if (grid.SelectedRows.Count > 1)
                {
                    if (!lblStatus.Text.Contains("auto-refresh paused")) lblStatus.Text += " · auto-refresh paused while several rows are selected";
                    return;
                }
                await LoadAsync(true);
            };
            lblStatus.Text = "Press \"Load\" to load Sysmon events.";
            ApplySettings();
        }

        /// <summary>
        /// Filters as a grid of "label | field" pairs with aligned columns: 4 pairs per row in a wide window,
        /// 2 pairs in a narrow one; the buttons on the last row.
        /// </summary>
        void ArrangeFilters()
        {
            int width = filters.ClientSize.Width - filters.Padding.Horizontal;
            if (width <= 0) return;
            int pairs = width >= Ui.S(1050) ? 4 : 2;
            if (pairs != filterPairs) BuildFilterGrid(pairs);
            int height = filterGrid.GetPreferredSize(new Size(width, 0)).Height;
            if (filterGrid.Height != height) filterGrid.Height = height;
            if (filters.Height != height + filters.Padding.Vertical) filters.Height = height + filters.Padding.Vertical;
        }

        void BuildFilterGrid(int pairs)
        {
            filterPairs = pairs;
            filterGrid.SuspendLayout();
            filterGrid.Controls.Clear();
            filterGrid.ColumnStyles.Clear();
            filterGrid.RowStyles.Clear();
            filterGrid.ColumnCount = pairs * 2;
            filterGrid.RowCount = (filterFields.Length + pairs - 1) / pairs + 1;
            // the first field (Event ID + Filter) gets more room in the wide layout
            float[] weights = pairs == 4 ? new[] { 31f, 23f, 23f, 23f } : new[] { 50f, 50f };
            foreach (float w in weights)
            {
                filterGrid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                filterGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, w));
            }
            for (int i = 0; i < filterFields.Length; i++)
            {
                int col = (i % pairs) * 2, row = i / pairs;
                filterGrid.Controls.Add(filterLabels[i], col, row);
                filterGrid.Controls.Add(filterFields[i].Control, col + 1, row);
            }
            filterGrid.Controls.Add(filterActions, 0, filterGrid.RowCount - 1);
            filterGrid.SetColumnSpan(filterActions, pairs * 2);
            filterGrid.ResumeLayout(true);
        }

        public void ApplySettings()
        {
            numMax.Value = s.MaxEvents;
            timer.Interval = Math.Max(2, s.RefreshSeconds) * 1000;
            timer.Enabled = s.AutoRefresh;
        }

        public async Task EnsureLoadedAsync()
        {
            if (!loadedOnce) await LoadAsync(true);
        }

        void ClearFilters()
        {
            cboId.SelectedIndex = 0;
            txtProc.Value = txtUser.Value = txtText.Value = "";
        }

        /// <summary>Sets the Event ID filter (negative number = exclude the ID) and loads the events.</summary>
        public async Task ShowIdsAsync(List<int> ids)
        {
            ids = ids.Distinct().ToList();
            int item = -1;
            if (ids.Count == 1 && ids[0] > 0)
                for (int i = 1; i < cboId.Items.Count; i++)
                    if (cboId.Items[i].ToString().StartsWith(ids[0] + " - ")) { item = i; break; }
            if (item >= 0) cboId.SelectedIndex = item;
            else cboId.Text = string.Join(",", ids.OrderBy(Math.Abs).Select(i => i < 0 ? "!" + (-i) : i.ToString()));
            if (loading) { await ReloadAsync(); return; }
            await LoadAsync(false);
        }

        SysmonQuery BuildQuery()
        {
            var q = new SysmonQuery
            {
                Process = txtProc.Value.Trim(),
                User = txtUser.Value.Trim(),
                Text = txtText.Value.Trim(),
                Max = numMax.Value
            };
            ParseIds(cboId.Text, q);
            time.GetRange(out q.From, out q.To);
            return q;
        }

        static void ParseIds(string text, SysmonQuery q)
        {
            if (string.IsNullOrWhiteSpace(text) || text.StartsWith("All")) return;
            int dash = text.IndexOf(" - ", StringComparison.Ordinal);
            if (dash > 0) text = text.Substring(0, dash);
            foreach (var part in text.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string p = part.Trim();
                bool neg = p.StartsWith("!");
                if (neg) p = p.Substring(1);
                if (!int.TryParse(p, out var id)) throw new FormatException($"Invalid Event ID: \"{part}\". Enter e.g. 1,3,22 or !7.");
                (neg ? q.ExcludeIds : q.IncludeIds).Add(id);
            }
        }

        /// <summary>Filter, Enter, a cell menu item: a running load is stopped and started again with the new filters.</summary>
        Task ReloadAsync()
        {
            if (!loading) return LoadAsync(false);
            restartPending = true;
            cts?.Cancel();
            return Task.CompletedTask;
        }

        public async Task LoadAsync(bool auto)
        {
            if (loading) { if (!auto) { restartPending = false; cts?.Cancel(); } return; }   // the Stop button
            SysmonQuery q;
            try { q = BuildQuery(); }
            catch (Exception ex) { Ui.Warn(this, ex.Message); return; }

            loading = true;
            loadedOnce = true;
            btnLoad.Text = "Stop";
            lblStatus.Text = "Loading Sysmon events…";
            cts = new CancellationTokenSource();
            var token = cts.Token;
            var sw = Stopwatch.StartNew();
            try
            {
                var res = await Task.Run(() => SysmonReader.Read(q, token));
                Bind(res.Events);
                lblStatus.ForeColor = Theme.SubText;
                lblStatus.Text = $"Showing {res.Events.Count} events · {res.Scanned} records scanned"
                                 + (res.ScanLimitReached ? " (scan limit reached – narrow the time window)" : "")
                                 + (token.IsCancellationRequested ? " · stopped" : "")
                                 + $" · {sw.Elapsed.TotalSeconds:0.00} s · updated {DateTime.Now:HH:mm:ss}";
            }
            catch (Exception ex)
            {
                lblStatus.ForeColor = Theme.Error;
                lblStatus.Text = "Error: " + ex.Message;
                if (!auto) Ui.Warn(this, ex.Message);
            }
            finally
            {
                loading = false;
                btnLoad.Text = "Load";
            }
            if (restartPending)
            {
                restartPending = false;
                await LoadAsync(false);
            }
        }

        void Bind(List<SysmonEvent> list)
        {
            long? selected = Selected()?.RecordId;
            events = list;
            table.BeginLoadData();
            table.Rows.Clear();
            for (int i = 0; i < list.Count; i++)
            {
                var e = list[i];
                table.Rows.Add(i, e.Time, e.EventId, e.TypeName, e.Image, e.ProcessId, e.User, e.Summary, e.RecordId);
            }
            table.EndLoadData();

            if (selected.HasValue)
                foreach (DataGridViewRow r in grid.Rows)
                    if (r.DataBoundItem is DataRowView rv && (long)rv["RecordId"] == selected.Value)
                    {
                        grid.CurrentCell = r.Cells["Time"];
                        break;
                    }
            ShowDetail();
        }

        SysmonEvent Selected()
        {
            if (grid.CurrentRow?.DataBoundItem is DataRowView rv)
            {
                int i = (int)rv["_idx"];
                if (i >= 0 && i < events.Count) return events[i];
            }
            return null;
        }

        void ShowDetail() => txtDetail.Display(Selected());

        /// <summary>AI analyzer over the shown / selected events (a snapshot – later reloads do not change it).</summary>
        void OpenAiAnalyzer()
        {
            if (events.Count == 0) { Ui.Warn(this, "Load events first – the AI analyzer works with the events shown in the table."); return; }
            var selected = grid.SelectedRows.Cast<DataGridViewRow>()
                .Select(r => r.DataBoundItem as DataRowView).Where(rv => rv != null)
                .Select(rv => events[(int)rv["_idx"]]).OrderByDescending(e => e.Time).ToList();
            var parts = new List<string> { "event ID " + cboId.Text, "time " + time.Preset.Text };
            if (txtProc.Value.Trim().Length > 0) parts.Add("process contains \"" + txtProc.Value.Trim() + "\"");
            if (txtUser.Value.Trim().Length > 0) parts.Add("user contains \"" + txtUser.Value.Trim() + "\"");
            if (txtText.Value.Trim().Length > 0) parts.Add("text \"" + txtText.Value.Trim() + "\" (prefix ! = excluded)");
            parts.Add("max. " + numMax.Value + " events");
            new AiAnalyzerForm(s, SysmonAi.Source(events, selected, string.Join("; ", parts))).Show(FindForm());
        }

        void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || !(grid.Rows[e.RowIndex].DataBoundItem is DataRowView rv)) return;
            if (rv["ID"] is int id && Suspicious.Contains(id))
            {
                e.CellStyle.BackColor = Theme.SuspiciousBg;
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.SuspiciousText;
                e.CellStyle.SelectionBackColor = Theme.SuspiciousSelected;
            }
        }
    }
}
