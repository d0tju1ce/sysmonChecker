using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace SysmonChecker
{
    enum Weight { Regular, SemiBold, Bold, ExtraBold }

    /// <summary>Dark theme: colour palette, embedded Nunito Sans font and drawing helpers.</summary>
    static class Theme
    {
        // palette
        public static readonly Color Sidebar = Hex(0x9FB294), SidebarLine = Hex(0xB2C2A8), SidebarHover = Hex(0xAEBFA3), SidebarText = Color.Black, SidebarSubText = Hex(0x2A3326);
        public static readonly Color NavSelected = Hex(0xEAD7CC), NavSelectedHover = Hex(0xF3E7DF);
        public static readonly Color Accent = Hex(0xFFC700), AccentHover = Hex(0xFFD54A), AccentText = Hex(0x170C00);
        public static readonly Color Bg = Hex(0x262626), Surface = Hex(0x2E2E2E), Input = Hex(0x222222), Button = Hex(0x383838), Hover = Hex(0x404040);
        public static readonly Color Border = Hex(0x565656), Line = Hex(0x3A3A3A);
        public static readonly Color Text = Color.White, SubText = Hex(0xA8A8A8), Muted = Hex(0x767676);
        // one colour for everything that needs attention – the light beige of the buttons (no red in the application):
        // suspicious rows (beige fill, dark text), warnings, errors and problematic values
        public static readonly Color Attention = NavSelected;
        public static readonly Color SuspiciousBg = Attention, SuspiciousSelected = NavSelectedHover, SuspiciousText = AccentText;
        public static readonly Color Orange = Hex(0xD24400), Ok = Hex(0x4CC38A), Warn = Attention, Error = Attention;

        static Color Hex(int rgb) => Color.FromArgb((rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);

        // fonts
        static readonly PrivateFontCollection pfc = new PrivateFontCollection();
        static readonly Dictionary<string, Font> cache = new Dictionary<string, Font>();
        static FontFamily famRegular, famSemiBold, famExtraBold;
        static readonly System.Collections.Generic.List<FileStream> heldFonts = new System.Collections.Generic.List<FileStream>();
        static string fontDir;   // per-run folder of an elevated process

        /// <summary>At exit of an elevated process: its font folder in C:\Windows\Temp is removed.</summary>
        public static void UnloadFonts()
        {
            if (fontDir == null) return;
            foreach (var h in heldFonts)
            {
                try { RemoveFontResourceEx(h.Name, FR_PRIVATE, IntPtr.Zero); } catch { }
                h.Dispose();
            }
            heldFonts.Clear();
            try { Directory.Delete(fontDir, true); } catch { }   // GDI+ may still hold the files – removed at a later start
        }

        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)]
        static extern bool RemoveFontResourceEx(string name, uint fl, IntPtr pdv);

        public static FontFamily LogoFamily => famExtraBold ?? famRegular ?? FontFamily.GenericSansSerif;

        /// <summary>
        /// Loads Nunito Sans embedded in the exe – for GDI+ and for GDI (TextRenderer). The fonts are extracted to
        /// %TEMP%\sysmonChecker\fonts (elevated: a new folder in C:\Windows\Temp, removed at exit), because
        /// PrivateFontCollection.AddMemoryFont drops some weights. Each file is verified while it is locked against writing.
        /// The STAT table in the embedded fonts is renamed (STAx) – otherwise GDI+ names the family
        /// "Nunito Sans Normal" while GDI knows it as "Nunito Sans" and the controls fall back to another font.
        /// </summary>
        public static void LoadFonts()
        {
            var asm = typeof(Theme).Assembly;
            string dir = Path.Combine(Path.GetTempPath(), Program.AppName, "fonts");
            // elevated: not the user's %TEMP% (a process of the user could swap the files or plant a junction there),
            // but a new folder in C:\Windows\Temp that only this administrator process can change
            if (SystemChecks.IsAdmin())
                try { dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp", Program.AppName + "-fonts-" + Guid.NewGuid().ToString("N")); }
                catch { }
            foreach (var name in new[] { "NunitoSans-Regular.ttf", "NunitoSans-SemiBold.ttf", "NunitoSans-Bold.ttf", "NunitoSans-ExtraBold.ttf" })
            {
                try
                {
                    using (var st = asm.GetManifestResourceStream(name))
                    {
                        if (st == null) continue;
                        string path = Path.Combine(dir, name);
                        var data = new byte[st.Length];
                        int read = 0;
                        while (read < data.Length) read += st.Read(data, read, data.Length - read);
                        if (!File.Exists(path) || !File.ReadAllBytes(path).SequenceEqual(data))
                        {
                            Directory.CreateDirectory(dir);
                            File.WriteAllBytes(path, data);
                        }
                        // the file stays open without write sharing for the whole run: it is checked under this lock and
                        // nobody can replace it between the check and the loading (or later)
                        var hold = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                        var onDisk = new byte[hold.Length];
                        int got = 0;
                        while (got < onDisk.Length) { int n = hold.Read(onDisk, got, onDisk.Length - got); if (n <= 0) break; got += n; }
                        if (!onDisk.SequenceEqual(data)) { hold.Dispose(); continue; }
                        heldFonts.Add(hold);
                        pfc.AddFontFile(path);
                        AddFontResourceEx(path, FR_PRIVATE, IntPtr.Zero);
                    }
                }
                catch { }
            }
            if (SystemChecks.IsAdmin())
            {
                fontDir = dir;
                // folders of earlier elevated runs that could not be removed (fonts were still in use)
                try
                {
                    foreach (var old in Directory.GetDirectories(Path.GetDirectoryName(dir), Program.AppName + "-fonts-*"))
                        if (!string.Equals(old, dir, StringComparison.OrdinalIgnoreCase) && Directory.GetCreationTimeUtc(old) < DateTime.UtcNow.AddHours(-1))
                            try { Directory.Delete(old, true); } catch { }
                }
                catch { }
            }
            foreach (var f in pfc.Families)
            {
                if (f.Name.EndsWith("SemiBold")) famSemiBold = f;
                else if (f.Name.EndsWith("ExtraBold")) famExtraBold = f;
                else if (f.Name.StartsWith("Nunito Sans")) famRegular = f;
            }
        }

        public static Font F(float size, Weight w = Weight.Regular)
        {
            string key = size + "|" + w;
            if (cache.TryGetValue(key, out var f)) return f;
            FontFamily fam = w == Weight.SemiBold ? famSemiBold : w == Weight.ExtraBold ? famExtraBold : famRegular;
            var style = w == Weight.Bold ? FontStyle.Bold : FontStyle.Regular;
            f = fam != null ? new Font(fam, size, style) : new Font("Segoe UI", size, w == Weight.Regular ? FontStyle.Regular : FontStyle.Bold);
            cache[key] = f;
            return f;
        }

        public static readonly Font Mono = new Font("Consolas", 9.5f);

        // drawing helpers
        public static GraphicsPath Round(RectangleF r, float radius)
        {
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            var p = new GraphicsPath();
            if (d <= 0) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        /// <summary>Clears the control with its parent's colour and draws a rounded box.</summary>
        public static void PaintBox(Graphics g, Control c, Color fill, Color border, int radius)
        {
            g.Clear(c.Parent?.BackColor ?? Bg);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = Round(new RectangleF(0.5f, 0.5f, c.Width - 1.5f, c.Height - 1.5f), radius))
            {
                using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                if (border != Color.Empty) using (var pen = new Pen(border)) g.DrawPath(pen, path);
            }
        }

        // native window theming
        const uint FR_PRIVATE = 0x10;
        [DllImport("gdi32.dll", CharSet = CharSet.Unicode)] static extern int AddFontResourceEx(string name, uint fl, IntPtr res);
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string appName, string idList);

        /// <summary>Dark title bar (Windows 10 20H1+) in the background colour (Windows 11).</summary>
        public static void DarkTitleBar(Form f)
        {
            try
            {
                int on = 1, caption = ColorTranslator.ToWin32(Bg), text = ColorTranslator.ToWin32(Text);
                DwmSetWindowAttribute(f.Handle, 20, ref on, 4);
                DwmSetWindowAttribute(f.Handle, 35, ref caption, 4);
                DwmSetWindowAttribute(f.Handle, 36, ref text, 4);
            }
            catch { }
        }

        /// <summary>Dark scroll bars for native controls (TextBox, DataGridView scroll bars, list boxes).</summary>
        public static void DarkScrollBars(Control c)
        {
            void apply() { try { SetWindowTheme(c.Handle, "DarkMode_Explorer", null); } catch { } }
            if (c.IsHandleCreated) apply(); else c.HandleCreated += (s, e) => apply();
        }

        public static void DarkScrollBars(IntPtr hwnd)
        {
            try { SetWindowTheme(hwnd, "DarkMode_Explorer", null); } catch { }
        }
    }

    /// <summary>Renderer for context menus in the dark theme.</summary>
    class DarkMenuRenderer : ToolStripProfessionalRenderer
    {
        public DarkMenuRenderer() : base(new DarkColors()) { RoundedEdges = false; }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = Theme.Text;
            base.OnRenderItemText(e);
        }

        class DarkColors : ProfessionalColorTable
        {
            public override Color ToolStripDropDownBackground => Theme.Surface;
            public override Color ImageMarginGradientBegin => Theme.Surface;
            public override Color ImageMarginGradientMiddle => Theme.Surface;
            public override Color ImageMarginGradientEnd => Theme.Surface;
            public override Color MenuBorder => Theme.Border;
            public override Color MenuItemBorder => Theme.Hover;
            public override Color MenuItemSelected => Theme.Hover;
            public override Color SeparatorDark => Theme.Line;
            public override Color SeparatorLight => Theme.Line;
        }
    }
}
