namespace CampusAuth;

internal static class Program
{
    private const string MutexName = @"Global\CampusAuth_SingleInstance_9F2A";
    private const string ShowEventName = @"Global\CampusAuth_ShowWindow_9F2A";

    [STAThread]
    private static void Main(string[] args)
    {
        using var mutex = new Mutex(true, MutexName, out bool created);

        if (!created)
        {
            // 已经在运行：让已有实例把窗口弹出来
            try
            {
                using var show = EventWaitHandle.OpenExisting(ShowEventName);
                show.Set();
            }
            catch
            {
                MessageBox.Show("校园网自动认证已经在运行了，请在任务栏右下角的托盘图标里查看。",
                    "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            return;
        }

        using var showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);

        ApplicationConfiguration.Initialize();

        // 兜底：任何未处理异常都写日志，不让程序静默退出
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => Log.Error("界面异常：" + e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Log.Error("未处理异常：" + e.ExceptionObject);

        if (args.Any(a => a.Equals("--diag", StringComparison.OrdinalIgnoreCase)))
        {
            try { Diag.RunAsync().GetAwaiter().GetResult(); }
            catch (Exception ex) { Log.Error("诊断失败：" + ex); }
            return;
        }

        bool startHidden = args.Any(a => a.Equals("--min", StringComparison.OrdinalIgnoreCase));
        Application.Run(new MainForm(startHidden, showSignal));
    }
}
