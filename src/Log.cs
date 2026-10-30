using System.Text;

namespace CampusAuth;

public enum LogLevel { Debug, Info, Warn, Error }

public static class Log
{
    private static readonly object Gate = new();
    private static string _dir = "";

    public static event Action<LogLevel, string>? Written;

    private static string Dir
    {
        get
        {
            if (_dir.Length > 0) return _dir;
            _dir = Path.Combine(AppConfig.ConfigDir, "logs");
            try { Directory.CreateDirectory(_dir); } catch { }
            return _dir;
        }
    }

    public static string LogFilePath => Path.Combine(Dir, $"app-{DateTime.Now:yyyyMMdd}.log");

    public static void Debug(string msg) => Write(LogLevel.Debug, msg);
    public static void Info(string msg) => Write(LogLevel.Info, msg);
    public static void Warn(string msg) => Write(LogLevel.Warn, msg);
    public static void Error(string msg) => Write(LogLevel.Error, msg);

    private static void Write(LogLevel level, string msg)
    {
        string line = $"{DateTime.Now:HH:mm:ss} [{level}] {msg}";
        lock (Gate)
        {
            try
            {
                if (File.Exists(LogFilePath) && new FileInfo(LogFilePath).Length > 2 * 1024 * 1024)
                {
                    File.Delete(LogFilePath);
                }
                File.AppendAllText(LogFilePath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }
        try { Written?.Invoke(level, line); } catch { }
    }

    /// <summary>清理 7 天前的日志</summary>
    public static void Cleanup()
    {
        try
        {
            foreach (var f in Directory.GetFiles(Dir, "app-*.log"))
            {
                if (File.GetLastWriteTime(f) < DateTime.Now.AddDays(-7)) File.Delete(f);
            }
        }
        catch { }
    }
}
