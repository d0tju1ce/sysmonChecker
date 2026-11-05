using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace SysmonChecker
{
    /// <summary>
    /// Detail of one Sysmon event: "name  value" rows, names grey, values white. Long values wrap under the value
    /// column (no horizontal scrolling); CallTrace and Hashes are split into one entry per line.
    /// </summary>
    class EventDetailView : RichTextBox
    {
        public EventDetailView()
        {
            Dock = DockStyle.Fill;
            BorderStyle = BorderStyle.None;
            ReadOnly = true;
            WordWrap = true;
            ScrollBars = RichTextBoxScrollBars.Vertical;
            DetectUrls = false;
            Font = Theme.Mono;
            BackColor = Theme.Surface;   // after ReadOnly – otherwise the control turns grey
            ForeColor = Theme.Text;
            Theme.DarkScrollBars(this);
        }

        public void Display(SysmonEvent e)
        {
            SuspendDrawing();
            try
            {
                Clear();
                if (e == null) return;
                var rows = new List<KeyValuePair<string, string>>
                {
                    Pair("Time", e.Time.ToString(Ui.DateFormatMs)),
                    Pair("Event ID", e.EventId + " – " + e.TypeName),
                    Pair("Record ID", e.RecordId.ToString()),
                    Pair("Computer", e.Computer),
                };
                int keyChars = rows.Concat(e.Fields).Max(r => r.Key.Length) + 2;
                int indent = TextRenderer.MeasureText(new string('0', keyChars), Font, Size.Empty, TextFormatFlags.NoPadding).Width;

                foreach (var r in rows) AppendRow(r.Key, new[] { r.Value }, indent);
                AppendSeparator();
                foreach (var f in e.Fields) AppendRow(f.Key, Split(f.Key, f.Value), indent);
                // tab stop at the value column for all rows
                SelectAll();
                SelectionTabs = new[] { indent };
                Select(0, 0);
            }
            finally { ResumeDrawing(); }
        }

        static KeyValuePair<string, string> Pair(string k, string v) => new KeyValuePair<string, string>(k, v);

        /// <summary>Values that are lists in one string – one entry per line.</summary>
        static IEnumerable<string> Split(string key, string value)
        {
            if (string.IsNullOrEmpty(value)) return new[] { "" };
            if (key == "CallTrace") return value.Split('|');
            if (key == "Hashes") return value.Split(',');
            return value.Replace("\r\n", "\n").Split('\n');
        }

        /// <summary>First line: name + value; wrapped and further lines start under the value (hanging indent).</summary>
        void AppendRow(string key, IEnumerable<string> lines, int indent)
        {
            bool first = true;
            foreach (var line in lines)
            {
                SelectionStart = TextLength;
                SelectionIndent = 0;
                SelectionHangingIndent = indent;
                if (first)
                {
                    SelectionColor = Theme.SubText;
                    AppendText(key + ":\t");
                }
                else
                {
                    SelectionColor = Theme.SubText;
                    AppendText("\t");
                }
                SelectionColor = Theme.Text;
                AppendText(line + "\n");
                first = false;
            }
        }

        void AppendSeparator()
        {
            SelectionStart = TextLength;
            SelectionIndent = SelectionHangingIndent = 0;
            SelectionColor = Theme.Line;
            AppendText(new string('─', 60) + "\n");
        }

        // ---- no flicker while the text is rebuilt
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr w, IntPtr l);
        const int WM_SETREDRAW = 0x000B;

        void SuspendDrawing() { if (IsHandleCreated) SendMessage(Handle, WM_SETREDRAW, IntPtr.Zero, IntPtr.Zero); }

        void ResumeDrawing()
        {
            if (!IsHandleCreated) return;
            SendMessage(Handle, WM_SETREDRAW, (IntPtr)1, IntPtr.Zero);
            Invalidate();
        }
    }
}
