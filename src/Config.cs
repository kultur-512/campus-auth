using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CampusAuth;

public class AppConfig
{
    /// <summary>校园网账号</summary>
    public string Username { get; set; } = "";
    /// <summary>加密后的密码（本机绑定，换机器需重填）</summary>
    public string PasswordCipher { get; set; } = "";
    /// <summary>门户地址，留空则自动探测，例如 http://10.10.10.10</summary>
    public string PortalUrl { get; set; } = "";
    /// <summary>自定义联网检测地址，留空用内置的</summary>
    public string ProbeUrl { get; set; } = "";
    /// <summary>ac_id，0 表示自动获取</summary>
    public int AcId { get; set; } = 0;
    /// <summary>断网检测间隔（秒）</summary>
    public int IntervalSeconds { get; set; } = 8;
    /// <summary>连续多少次检测失败才判定为掉线</summary>
    public int FailThreshold { get; set; } = 2;
    /// <summary>开机自启</summary>
    public bool AutoStart { get; set; }
    /// <summary>启动后自动开始守护</summary>
    public bool AutoRun { get; set; } = true;
    /// <summary>关闭窗口时最小化到托盘</summary>
    public bool MinimizeToTray { get; set; } = true;
    /// <summary>会话保活间隔（秒），0 表示关闭</summary>
    public int KeepAliveSeconds { get; set; } = 300;
    /// <summary>自动认证失败时，改为启动官方客户端兜底</summary>
    public bool FallbackEnabled { get; set; }
    /// <summary>窗口宽高（记住上次大小）</summary>
    public int WindowWidth { get; set; }
    public int WindowHeight { get; set; }
    /// <summary>兜底要启动的程序路径</summary>
    public string FallbackCommand { get; set; } = "";

    [System.Text.Json.Serialization.JsonIgnore]
    public string Password
    {
        get => PasswordCipher.Length == 0 ? "" : Secret.Decrypt(PasswordCipher);
        set => PasswordCipher = value.Length == 0 ? "" : Secret.Encrypt(value);
    }

    public static string ConfigDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CampusAuth");

    public static string ConfigPath => Path.Combine(ConfigDir, "config.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static AppConfig Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var cfg = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(ConfigPath), JsonOpts);
                if (cfg != null) return cfg;
            }
        }
        catch (Exception ex)
        {
            Log.Warn("读取配置失败，使用默认配置：" + ex.Message);
        }
        return new AppConfig();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch (Exception ex)
        {
            Log.Warn("保存配置失败：" + ex.Message);
        }
    }
}

/// <summary>用本机信息派生的密钥做 AES 加密，避免明文保存密码。</summary>
internal static class Secret
{
    private static byte[] Key()
    {
        string seed = Environment.MachineName + "|" + Environment.UserName + "|CampusAuth.v1";
        return SHA256.HashData(Encoding.UTF8.GetBytes(seed));
    }

    public static string Encrypt(string plain)
    {
        try
        {
            byte[] data = Encoding.UTF8.GetBytes(plain);
            using var aes = Aes.Create();
            aes.Key = Key();
            aes.GenerateIV();
            using var enc = aes.CreateEncryptor();
            byte[] cipher = enc.TransformFinalBlock(data, 0, data.Length);
            var outBuf = new byte[aes.IV.Length + cipher.Length];
            aes.IV.CopyTo(outBuf, 0);
            cipher.CopyTo(outBuf, aes.IV.Length);
            return Convert.ToBase64String(outBuf);
        }
        catch
        {
            return "";
        }
    }

    public static string Decrypt(string cipherText)
    {
        try
        {
            byte[] all = Convert.FromBase64String(cipherText);
            using var aes = Aes.Create();
            aes.Key = Key();
            int ivLen = 16;
            if (all.Length <= ivLen) return "";
            aes.IV = all.AsSpan(0, ivLen).ToArray();
            using var dec = aes.CreateDecryptor();
            byte[] plain = dec.TransformFinalBlock(all, ivLen, all.Length - ivLen);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return "";
        }
    }
}
