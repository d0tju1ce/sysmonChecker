using System;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;

namespace SysmonChecker
{
    /// <summary>"Event IDs" page: overview of the Sysmon event types; opens the Events page filtered by the selected IDs.</summary>
    class EventIdsTab : UserControl
    {
        readonly DataGridView grid = Ui.CreateGrid();
        readonly DataTable table = new DataTable();

        /// <summary>The user wants to see the events of these IDs.</summary>
        public event Action<List<int>> ShowEventsRequested;

        public EventIdsTab()
        {
            Dock = DockStyle.Fill;

            Ui.AddColumn(grid, table, "ID", "ID", typeof(int), 60);
            Ui.AddColumn(grid, table, "Type", "Event type", typeof(string), 230);
            Ui.AddColumn(grid, table, "Description", "What it records", typeof(string), 600, fill: true);
            Ui.AddColumn(grid, table, "Note", "Note", typeof(string), 110);
            foreach (var kv in SysmonReader.EventNames)
            {
                SysmonReader.EventDescriptions.TryGetValue(kv.Key, out var desc);
                table.Rows.Add(kv.Key, kv.Value, desc ?? "", SysmonTab.Suspicious.Contains(kv.Key) ? "suspicious" : "");
            }
            grid.DataSource = table;
            grid.CellFormatting += Grid_CellFormatting;
            grid.CellPainting += Grid_CellPainting;
            grid.CellDoubleClick += (o, e) => { if (e.RowIndex >= 0) Request(new List<int> { IdOf(grid.Rows[e.RowIndex]) }); };
            grid.KeyDown += (o, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; Request(SelectedIds()); } };

            var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Margin = new Padding(0) };
            var hint = Ui.L("Double-click an ID to show its events. Select more rows with Ctrl / Shift to filter by several IDs.");
            hint.Margin = new Padding(Ui.S(10), Ui.S(10), 0, 0);
            bar.Controls.AddRange(new Control[]
            {
                Ui.B("Show events of selected IDs", (o, e) => Request(SelectedIds()), ButtonKind.Primary),
                Ui.B("Show events except selected", (o, e) => Request(SelectedIds().Select(i => -i).ToList())),
                hint
            });
            var filters = new Card { Dock = DockStyle.Top, Padding = new Padding(Ui.S(10), Ui.S(8), Ui.S(10), Ui.S(8)) };
            filters.Controls.Add(bar);
            bar.SizeChanged += (o, e) => filters.Height = bar.Height + filters.Padding.Vertical;
            var gap = new Panel { Dock = DockStyle.Top, Height = Ui.S(10) };

            Controls.Add(grid);
            Controls.Add(gap);
            Controls.Add(filters);
        }

        /// <summary>Selects and scrolls to the row of the given ID.</summary>
        public void Highlight(int id)
        {
            foreach (DataGridViewRow r in grid.Rows)
                if (IdOf(r) == id)
                {
                    grid.ClearSelection();
                    grid.CurrentCell = r.Cells["ID"];
                    r.Selected = true;
                    break;
                }
            grid.Focus();
        }

        static int IdOf(DataGridViewRow r) => r.DataBoundItem is DataRowView rv ? (int)rv["ID"] : 0;

        List<int> SelectedIds() => grid.SelectedRows.Cast<DataGridViewRow>().Select(IdOf).OrderBy(i => i).ToList();

        /// <summary>Negative numbers = exclude the ID.</summary>
        void Request(List<int> ids)
        {
            if (ids.Count == 0) { Ui.Warn(this, "Select at least one event ID."); return; }
            ShowEventsRequested?.Invoke(ids);
        }

        /// <summary>"suspicious" in the Note column as a label in the button design (light beige, dark bold text).</summary>
        void Grid_CellPainting(object sender, DataGridViewCellPaintingEventArgs e)
        {
            if (e.RowIndex < 0 || grid.Columns[e.ColumnIndex].Name != "Note" || !(e.Value is string v) || v.Length == 0) return;
            // background + border as the grid draws them, only the text is replaced by the label
            e.Paint(e.CellBounds, DataGridViewPaintParts.All & ~DataGridViewPaintParts.ContentForeground);
            var font = Theme.F(9f, Weight.Bold);
            int w = TextRenderer.MeasureText(v, font).Width + Ui.S(18), h = Ui.S(24);
            var r = new Rectangle(e.CellBounds.X + Ui.S(6), e.CellBounds.Y + (e.CellBounds.Height - h) / 2, w, h);
            var state = e.Graphics.Save();   // the grid reuses the Graphics for the other cells
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Theme.Round(new RectangleF(r.X + 0.5f, r.Y + 0.5f, r.Width - 1, r.Height - 1), Ui.S(6)))
            using (var b = new SolidBrush(Theme.NavSelected))
                e.Graphics.FillPath(b, path);
            e.Graphics.Restore(state);
            TextRenderer.DrawText(e.Graphics, v, font, r, Theme.AccentText,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
            e.Handled = true;
        }

        void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || !(grid.Rows[e.RowIndex].DataBoundItem is DataRowView rv)) return;
            if (SysmonTab.Suspicious.Contains((int)rv["ID"]))
            {
                e.CellStyle.BackColor = Theme.SuspiciousBg;
                e.CellStyle.ForeColor = e.CellStyle.SelectionForeColor = Theme.SuspiciousText;
                e.CellStyle.SelectionBackColor = Theme.SuspiciousSelected;
            }
        }
    }
}
