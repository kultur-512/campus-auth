using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace CampusAuth;

/// <summary>诊断模式：把网络与门户探测结果写到文件，便于排查（--diag）。</summary>
internal static class Diag
{
    public static string ReportPath => Path.Combine(AppConfig.ConfigDir, "diag.txt");

    public static async Task RunAsync()
    {
        var sb = new StringBuilder();
        void W(string s) { sb.AppendLine(s); }

        W("校园网自动认证 · 诊断报告");
        W("时间：" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        W("主机：" + Environment.MachineName + "  用户：" + Environment.UserName);
        W("系统：" + Environment.OSVersion);
        W("");

        W("===== 网卡 =====");
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var props = ni.GetIPProperties();
            var ips = props.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()).ToArray();
            if (ips.Length == 0) continue;
            var gws = props.GatewayAddresses.Select(g => g.Address.ToString()).ToArray();
            W($"{ni.Name} [{ni.NetworkInterfaceType}] {ni.OperationalStatus}");
            W("   IP  : " + string.Join(", ", ips));
            W("   网关: " + string.Join(", ", gws));
            W("   DNS : " + string.Join(", ", props.DnsAddresses.Select(d => d.ToString())));
        }
        W("");

        using var client = new SrunClient();

        W("===== 联网检测 =====");
        bool online = await client.IsInternetOkAsync();
        W("可上网：" + (online ? "是" : "否（可能未认证）"));
        W("");

        W("===== 门户探测 =====");
        string? portal = await client.DiscoverPortalAsync();
        W("探测结果：" + (portal ?? "未找到"));
        W("");

        var cfg = AppConfig.Load();
        if (!string.IsNullOrWhiteSpace(cfg.PortalUrl)) W("配置中的门户：" + cfg.PortalUrl);
        W("");

        if (portal != null)
        {
            W("===== 门户状态 =====");
            W("本机通往门户的 IP：" + SrunClient.GetLocalIp(portal));
            var st = await client.QueryStatusAsync(portal);
            W("在线：" + st.Online);
            W("用户：" + st.UserName);
            W("IP  ：" + st.Ip);
            W("ac_id：" + st.AcId);
            W("原始：" + st.Raw);
            W("");
        }

        W("===== 直接探测常见地址 =====");
        using var http = new HttpClient(new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(4)
        })
        { Timeout = TimeSpan.FromSeconds(8) };

        foreach (var url in new[]
                 {
                     "http://connect.rom.miui.com/generate_204",
                     "http://www.msftconnecttest.com/connecttest.txt",
                     "http://www.baidu.com/"
                 })
        {
            try
            {
                using var resp = await http.GetAsync(url);
                string body = "";
                try { body = await resp.Content.ReadAsStringAsync(); } catch { }
                string head = body.Length > 120 ? body[..120].Replace("\r", " ").Replace("\n", " ") : body.Replace("\r", " ").Replace("\n", " ");
                W($"{url} → HTTP {(int)resp.StatusCode}  Location={(resp.Headers.Location?.ToString() ?? "-")}");
                W("   body: " + head);
            }
            catch (Exception ex)
            {
                W($"{url} → 失败：{ex.Message}");
            }
        }

        try
        {
            Directory.CreateDirectory(AppConfig.ConfigDir);
            File.WriteAllText(ReportPath, sb.ToString(), Encoding.UTF8);
        }
        catch { }
    }
}
