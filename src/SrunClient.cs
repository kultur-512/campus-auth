using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace CampusAuth;

public record LoginResult(bool Success, string Message);

public record PortalStatus(bool Online, string UserName, string Ip, string AcId, string Raw);

public class SrunClient : IDisposable
{
    private readonly HttpClient _http;

    // 门户探测用的探测地址（未认证时会被劫持/重定向到认证页）
    private static readonly string[] ProbeUrls =
    {
        "http://connect.rom.miui.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://captive.apple.com/hotspot-detect.html",
        "http://www.baidu.com/"
    };

    /// <summary>自定义联网检测地址（留空用内置列表）</summary>
    public string? CustomProbeUrl { get; set; }

    public SrunClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,                 // 不走系统代理，避免误判
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2)
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36");
        _http.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "*/*");
    }

    public void Dispose() => _http.Dispose();

    // ---------------- 基础 HTTP ----------------

    private async Task<(int Status, string Body, string? Location, string FinalUrl)> SendAsync(
        string url, HttpMethod? method = null, HttpContent? content = null, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(method ?? HttpMethod.Get, url) { Content = content };
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct);
        string body = "";
        try { body = await resp.Content.ReadAsStringAsync(ct); } catch { }
        string? loc = resp.Headers.Location?.ToString();
        return ((int)resp.StatusCode, body, loc, url);
    }

    // ---------------- 在线检测 ----------------

    /// <summary>检测是否真正能上网（未认证时会被门户拦截）。</summary>
    public async Task<bool> IsInternetOkAsync(CancellationToken ct = default)
    {
        var urls = string.IsNullOrWhiteSpace(CustomProbeUrl)
            ? ProbeUrls.Take(3)
            : new[] { CustomProbeUrl! }.AsEnumerable();

        foreach (var url in urls)
        {
            try
            {
                var (status, body, loc, _) = await SendAsync(url, ct: ct);
                if (status == 204) return true;
                if (status is >= 300 and < 400) return false;   // 被重定向 = 需要认证
                if (status == 200 && !LooksLikePortal(body)) return true;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // 继续尝试下一个
            }
        }
        return false;
    }

    private static bool LooksLikePortal(string body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        if (body.Length > 20000) body = body[..20000];
        return body.Contains("srun_portal", StringComparison.OrdinalIgnoreCase)
               || body.Contains("ac_id", StringComparison.OrdinalIgnoreCase)
               || body.Contains("深澜", StringComparison.Ordinal)
               || body.Contains("校园网", StringComparison.Ordinal)
               || body.Contains("请登录", StringComparison.Ordinal)
               || body.Contains("login", StringComparison.OrdinalIgnoreCase) && body.Contains("password", StringComparison.OrdinalIgnoreCase);
    }

    // ---------------- 门户探测 ----------------

    /// <summary>自动找到认证门户地址，例如 http://10.20.30.40 或 http://10.20.30.40:8080</summary>
    public async Task<string?> DiscoverPortalAsync(CancellationToken ct = default)
    {
        Log.Info("正在探测认证门户…");

        foreach (var url in ProbeUrls)
        {
            try
            {
                var (status, body, loc, _) = await SendAsync(url, ct: ct);
                string? candidate = null;

                if (status is >= 300 and < 400 && !string.IsNullOrEmpty(loc))
                {
                    candidate = ToBase(loc);
                }
                else if (status == 200 && LooksLikePortal(body))
                {
                    // 页面里可能带 meta refresh 或脚本跳转
                    var m = Regex.Match(body, @"url\s*=\s*['""]?(https?://[^'""\s>]+)", RegexOptions.IgnoreCase);
                    candidate = m.Success ? ToBase(m.Groups[1].Value) : ToBase(url);
                }

                if (candidate != null && await ValidatePortalAsync(candidate, ct))
                {
                    Log.Info("探测到门户：" + candidate);
                    return candidate;
                }
            }
            catch (Exception ex)
            {
                Log.Debug($"探测 {url} 失败：{ex.Message}");
            }
        }

        // 兜底 1：DNS 劫持探测——未认证时很多学校会把任意域名解析到门户
        var hijacked = await ProbeDnsHijackAsync(ct);
        if (hijacked != null) return hijacked;

        // 兜底 2：网关地址上常见的门户路径
        foreach (var gw in GetGatewayAddresses())
        {
            foreach (var candidate in new[] { $"http://{gw}", $"http://{gw}:8080", $"http://{gw}:801" })
            {
                if (await ValidatePortalAsync(candidate, ct))
                {
                    Log.Info("在网关处发现门户：" + candidate);
                    return candidate;
                }
            }
        }

        Log.Warn("未能自动探测到门户地址，请在设置里手动填写。");
        return null;
    }

    /// <summary>解析一个不存在的域名，如果返回内网地址，说明 DNS 被劫持到门户。</summary>
    private async Task<string?> ProbeDnsHijackAsync(CancellationToken ct)
    {
        string probe = "probe-" + Guid.NewGuid().ToString("N")[..10] + ".example.com";
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(probe, ct);
            foreach (var addr in addrs)
            {
                if (addr.AddressFamily != AddressFamily.InterNetwork) continue;
                string ip = addr.ToString();
                if (!IsPrivate(ip)) continue;

                foreach (var candidate in new[] { $"http://{ip}", $"http://{ip}:8080" })
                {
                    if (await ValidatePortalAsync(candidate, ct))
                    {
                        Log.Info("通过 DNS 劫持发现门户：" + candidate);
                        return candidate;
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private static bool IsPrivate(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return false;
        if (!byte.TryParse(parts[0], out byte a) || !byte.TryParse(parts[1], out byte b)) return false;
        if (a == 10) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 127) return false;
        return false;
    }

    private static string ToBase(string url)
    {
        try
        {
            var uri = new Uri(url);
            return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";
        }
        catch
        {
            return url.TrimEnd('/');
        }
    }

    /// <summary>验证候选地址是不是深澜门户。</summary>
    public async Task<bool> ValidatePortalAsync(string baseUrl, CancellationToken ct = default)
    {
        try
        {
            var (status, body, _, _) = await SendAsync(baseUrl + "/cgi-bin/rad_user_info?callback=cb&_=" + Ts(), ct: ct);
            if (status == 200 &&
                (body.Contains("online_ip", StringComparison.OrdinalIgnoreCase)
                 || body.Contains("not_online", StringComparison.OrdinalIgnoreCase)
                 || body.Contains("error_msg", StringComparison.OrdinalIgnoreCase)))
                return true;

            var (status2, body2, _, _) = await SendAsync(baseUrl + "/", ct: ct);
            return status2 == 200 && LooksLikePortal(body2);
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> GetGatewayAddresses()
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                foreach (var gw in ni.GetIPProperties().GatewayAddresses)
                {
                    var addr = gw.Address?.ToString();
                    if (!string.IsNullOrEmpty(addr) && addr != "0.0.0.0") result.Add(addr);
                }
            }
        }
        catch { }
        return result;
    }

    private static long Ts() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    // ---------------- 本机 IP ----------------

    /// <summary>取本机在校园网上的 IP（用路由选路得到，避免多网卡选错）。</summary>
    public static string GetLocalIp(string portalBase)
    {
        try
        {
            var uri = new Uri(portalBase);
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(uri.Host, uri.Port);
            return ((IPEndPoint)socket.LocalEndPoint!).Address.ToString();
        }
        catch
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Connect("223.5.5.5", 53);
                return ((IPEndPoint)socket.LocalEndPoint!).Address.ToString();
            }
            catch { return "0.0.0.0"; }
        }
    }

    // ---------------- ac_id ----------------

    public async Task<string> DiscoverAcIdAsync(string baseUrl, CancellationToken ct = default)
    {
        try
        {
            var (status, body, _, _) = await SendAsync(baseUrl + "/", ct: ct);
            if (status == 200)
            {
                var m = Regex.Match(body, @"ac_id['""]?\s*[:=]\s*['""]?(\d+)", RegexOptions.IgnoreCase);
                if (!m.Success) m = Regex.Match(body, @"acid['""]?\s*[:=]\s*['""]?(\d+)", RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Value;
            }
        }
        catch { }
        return "1";
    }

    // ---------------- 登录 ----------------

    public async Task<LoginResult> LoginAsync(string baseUrl, string username, string password, int acId,
        CancellationToken ct = default)
    {
        baseUrl = ToBase(baseUrl);
        string ip = GetLocalIp(baseUrl);
        string acid = acId > 0 ? acId.ToString() : await DiscoverAcIdAsync(baseUrl, ct);

        Log.Info($"开始认证：账号={username}  门户={baseUrl}  IP={ip}  ac_id={acid}");

        // 新版门户：先取 challenge，再按 token 加密
        var challenge = await GetChallengeAsync(baseUrl, username, ip, ct);
        if (challenge != null)
        {
            var (token, clientIp) = challenge.Value;
            if (!string.IsNullOrWhiteSpace(clientIp)) ip = clientIp;

            var v2 = await LoginWithChallengeAsync(baseUrl, username, password, acid, ip, token, ct);
            if (v2 != null) return v2;

            Log.Warn("challenge 方式请求失败，尝试老版接口…");
        }

        return await LoginLegacyProtocolAsync(baseUrl, username, password, acid, ip, ct);
    }

    /// <summary>取 challenge（新版深澜门户的握手接口）。</summary>
    private async Task<(string Token, string ClientIp)?> GetChallengeAsync(string baseUrl, string username,
        string ip, CancellationToken ct)
    {
        try
        {
            string url = baseUrl + "/cgi-bin/get_challenge?callback=cb" +
                         "&username=" + Uri.EscapeDataString(username) +
                         "&ip=" + Uri.EscapeDataString(ip) + "&_=" + Ts();
            var (status, body, _, _) = await SendAsync(url, ct: ct);
            string json = ExtractJson(body);
            if (status != 200 || json.Length == 0) return null;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (GetStr(root, "error") != "ok") return null;

            string token = GetStr(root, "challenge");
            if (token.Length == 0) return null;
            return (token, GetStr(root, "client_ip"));
        }
        catch (Exception ex)
        {
            Log.Debug("获取 challenge 失败：" + ex.Message);
            return null;
        }
    }

    /// <summary>按门户 JS 的 v2 流程认证。返回 null 表示请求本身失败，应回退老协议。</summary>
    private async Task<LoginResult?> LoginWithChallengeAsync(string baseUrl, string username, string password,
        string acid, string ip, string token, CancellationToken ct)
    {
        string hmd5 = SrunCrypto.HmacMd5Keyed(token, password);          // HMAC-MD5(key=token, msg=密码)
        string info = SrunCrypto.BuildInfoV2(username, password, ip, acid, token); // 注意用明文密码
        string chkstr = token + username + token + hmd5 + token + acid + token + ip +
                        token + "200" + token + "1" + token + info;
        string chksum = SrunCrypto.Sha1Hex(chkstr);

        string url = baseUrl + "/cgi-bin/srun_portal?callback=cb&action=login" +
                     "&username=" + Uri.EscapeDataString(username) +
                     "&password=" + Uri.EscapeDataString("{MD5}" + hmd5) +
                     "&ac_id=" + Uri.EscapeDataString(acid) +
                     "&ip=" + Uri.EscapeDataString(ip) +
                     "&chksum=" + chksum +
                     "&info=" + Uri.EscapeDataString(info) +
                     "&n=200&type=1&os=Windows+10&name=Windows&double_stack=0";

        try
        {
            var (status, body, _, _) = await SendAsync(url, ct: ct);
            if (status != 200 || ExtractJson(body).Length == 0) return null;
            return ParseLoginBody(body, status);
        }
        catch (Exception ex)
        {
            Log.Warn("请求 srun_portal 异常：" + ex.Message);
            return null;
        }
    }

    /// <summary>老版深澜协议：chksum 用固定密钥 "srun" 做 HMAC-MD5。</summary>
    private async Task<LoginResult> LoginLegacyProtocolAsync(string baseUrl, string username, string password,
        string acid, string ip, CancellationToken ct)
    {
        string encPwd = "{MD5}" + SrunCrypto.Md5Hex(password);
        string info = SrunCrypto.BuildInfo(username, encPwd, ip, acid);
        string chksum = SrunCrypto.BuildChecksum(username, encPwd, acid, ip, info);

        string url = baseUrl + "/cgi-bin/srun_portal?callback=jQuery&action=login" +
                     "&username=" + Uri.EscapeDataString(username) +
                     "&password=" + Uri.EscapeDataString(encPwd) +
                     "&ac_id=" + Uri.EscapeDataString(acid) +
                     "&ip=" + Uri.EscapeDataString(ip) +
                     "&chksum=" + chksum +
                     "&info=" + Uri.EscapeDataString(info) +
                     "&n=200&type=1&os=Windows+10&name=Windows&double_stack=0&enc_ver=srun_bx1";

        try
        {
            var (status, body, _, _) = await SendAsync(url, ct: ct);
            var result = ParseLoginBody(body, status);
            if (result.Success) return result;

            Log.Warn("老版 srun_portal 认证失败：" + result.Message + "，尝试 do_login…");
            return await LegacyLoginAsync(baseUrl, username, encPwd, ct);
        }
        catch (Exception ex)
        {
            Log.Warn("请求老版 srun_portal 异常：" + ex.Message + "，尝试 do_login…");
            return await LegacyLoginAsync(baseUrl, username, encPwd, ct);
        }
    }

    /// <summary>旧版深澜（SRun3000）do_login 接口。</summary>
    private async Task<LoginResult> LegacyLoginAsync(string baseUrl, string username, string encPwd, CancellationToken ct)
    {
        try
        {
            var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = username,
                ["password"] = encPwd,
                ["drop"] = "0",
                ["type"] = "1",
                ["n"] = "1"
            });
            var (status, body, _, _) = await SendAsync(baseUrl + "/cgi-bin/do_login", HttpMethod.Post, form, ct);
            body = body.Trim();

            if (body.StartsWith("ok", StringComparison.OrdinalIgnoreCase))
                return new LoginResult(true, "认证成功");

            string msg = body switch
            {
                "" => $"服务器返回空内容（HTTP {status}）",
                _ when body.All(char.IsDigit) => $"认证失败，错误码 {body}（密码错误或账号被限制）",
                _ => body.Length > 160 ? body[..160] : body
            };
            return new LoginResult(false, msg);
        }
        catch (Exception ex)
        {
            return new LoginResult(false, "请求失败：" + ex.Message);
        }
    }

    private static LoginResult ParseLoginBody(string body, int status)
    {
        string json = ExtractJson(body);
        if (json.Length == 0)
        {
            return new LoginResult(false, $"服务器返回异常（HTTP {status}）：{Truncate(body)}");
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string err = GetStr(root, "error");
            string errorMsg = GetStr(root, "error_msg");
            string sucMsg = GetStr(root, "suc_msg");
            string ployMsg = GetStr(root, "ploy_msg");

            if (err.Equals("ok", StringComparison.OrdinalIgnoreCase) || err.Equals("0", StringComparison.Ordinal))
            {
                string note = sucMsg.Length > 0 ? sucMsg : "认证成功";
                return new LoginResult(true, Translate(note));
            }

            string text = ployMsg.Length > 0 ? ployMsg
                : errorMsg.Length > 0 ? errorMsg
                : sucMsg.Length > 0 ? sucMsg
                : err;
            return new LoginResult(false, Translate(text.Length > 0 ? text : "认证失败（未知原因）"));
        }
        catch
        {
            return new LoginResult(false, "返回内容无法解析：" + Truncate(body));
        }
    }

    /// <summary>把门户返回的英文错误码翻成人话。</summary>
    private static string Translate(string code)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["login_ok"] = "认证成功",
            ["ip_already_online_error"] = "该 IP 已经在线（无需重复认证）",
            ["password_error"] = "账号或密码不正确",
            ["username_error"] = "账号格式不正确",
            ["user_not_found"] = "账号不存在",
            ["chksum_error"] = "校验失败（客户端算法与门户不匹配）",
            ["login_error"] = "认证被拒绝",
            ["not_online_error"] = "当前未在线",
            ["ac_id_error"] = "ac_id 不正确",
            ["ip_error"] = "IP 地址不正确",
            ["network_error"] = "网络异常，请稍后重试",
            ["radius_timeout"] = "认证服务器超时，请稍后重试",
            ["user_locked"] = "账号被锁定",
            ["insufficient_balance"] = "余额不足"
        };
        return map.TryGetValue(code, out var v) ? v : code;
    }

    private static string GetStr(JsonElement root, string name)
    {
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out var v))
        {
            return v.ValueKind switch
            {
                JsonValueKind.String => v.GetString() ?? "",
                JsonValueKind.Number => v.ToString(),
                _ => ""
            };
        }
        return "";
    }

    private static string ExtractJson(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";
        int start = body.IndexOf('{');
        int end = body.LastIndexOf('}');
        if (start < 0 || end <= start) return "";
        return body.Substring(start, end - start + 1);
    }

    private static string Truncate(string s) => s.Length > 160 ? s[..160].Replace("\n", " ") : s.Replace("\n", " ");

    // ---------------- 状态查询 ----------------

    public async Task<PortalStatus> QueryStatusAsync(string baseUrl, CancellationToken ct = default)
    {
        try
        {
            var (status, body, _, _) = await SendAsync(baseUrl + "/cgi-bin/rad_user_info?callback=cb&_=" + Ts(), ct: ct);
            string json = ExtractJson(body);
            if (status != 200 || json.Length == 0)
                return new PortalStatus(false, "", "", "", $"HTTP {status}");

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            string err = GetStr(root, "error");
            bool online = err.Equals("ok", StringComparison.OrdinalIgnoreCase);
            return new PortalStatus(online,
                GetStr(root, "user_name"),
                GetStr(root, "online_ip"),
                GetStr(root, "ac_id"),
                json);
        }
        catch (Exception ex)
        {
            return new PortalStatus(false, "", "", "", ex.Message);
        }
    }

    /// <summary>保活：查询一次在线信息，让会话不被判定为空闲。</summary>
    public async Task KeepAliveAsync(string baseUrl, CancellationToken ct = default)
    {
        try
        {
            await SendAsync(baseUrl + "/cgi-bin/rad_user_info?callback=cb&_=" + Ts(), ct: ct);
            // 顺带访问一次门户首页，部分学校以流量判断保活
            await SendAsync(baseUrl + "/", ct: ct);
        }
        catch { }
    }
}
