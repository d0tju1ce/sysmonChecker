using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SysmonChecker
{
    static class Program
    {
        public const string AppName = "sysmonChecker";

        /// <summary>Error log of this Windows user on this computer – not in the application folder (it is not copied with it).</summary>
        public static string ErrorLogPath =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppName, "error.log");

        const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetDefaultDllDirectories(uint flags);

        [STAThread]
        static void Main(string[] args)
        {
            // DLLs loaded from now on come only from System32 – not from the application folder or the current folder
            // (a DLL planted next to the exe must not be loaded, also not in the elevated process)
            try { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32); } catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            // errors in the UI thread: short message, details only in the log
            Application.ThreadException += (s, e) =>
            {
                LogError("UI", e.Exception);
                MessageBox.Show(e.Exception.GetBaseException().Message + "\n\nDetails were written to " + ErrorLogPath,
                    AppName + " – unexpected error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            // errors outside the UI thread would end the application without a word – at least log them
            AppDomain.CurrentDomain.UnhandledException += (s, e) => LogError("background thread (application ends)", e.ExceptionObject as Exception);
            TaskScheduler.UnobservedTaskException += (s, e) => { LogError("task", e.Exception); e.SetObserved(); };

            Theme.LoadFonts();
            Application.ApplicationExit += (s, e) => Theme.UnloadFonts();
            if (args.Length == 2 && args[0] == "--export-logo") { Logo.Export(args[1], Theme.LogoFamily); return; }
            Application.Run(new MainForm());
        }

        static readonly object logLock = new object();

        public static void LogError(string where, Exception ex)
        {
            try
            {
                lock (logLock)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(ErrorLogPath));
                    var fi = new FileInfo(ErrorLogPath);
                    if (fi.Exists && fi.Length > 1024 * 1024)   // keep it small
                    {
                        File.Delete(ErrorLogPath + ".old");
                        File.Move(ErrorLogPath, ErrorLogPath + ".old");
                    }
                    File.AppendAllText(ErrorLogPath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{where}] {ex}\r\n\r\n");
                }
            }
            catch { }
        }
    }
}
