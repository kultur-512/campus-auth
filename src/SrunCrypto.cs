using System.Security.Cryptography;
using System.Text;

namespace CampusAuth;

/// <summary>
/// 深澜（SRun）门户认证用到的加密算法：
/// 密码 {MD5}、info 的 SRBX1 编码、chksum 的 HMAC-MD5。
/// </summary>
public static class SrunCrypto
{
    // 深澜自定义 base64 字母表
    private const string CustomAlphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
    private const string StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static string Md5Hex(string s) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    public static string Sha1Hex(string s) =>
        Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    /// <summary>HMAC-MD5，key 在前（对应门户 JS 里的 md5(msg, key)）。</summary>
    public static string HmacMd5Keyed(string key, string message)
    {
        using var h = new HMACMD5(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(message))).ToLowerInvariant();
    }

    public static string HmacMd5Hex(string message, string key)
    {
        using var h = new HMACMD5(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(message))).ToLowerInvariant();
    }

    private static int At(byte[] b, int i) => i < b.Length ? b[i] : 0;

    private static uint[] SEncode(string msg, bool key)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(msg);
        int len = bytes.Length;
        var pwd = new List<uint>(len / 4 + 2);
        for (int i = 0; i < len; i += 4)
        {
            pwd.Add((uint)(At(bytes, i) | At(bytes, i + 1) << 8 | At(bytes, i + 2) << 16 | At(bytes, i + 3) << 24));
        }
        if (key) pwd.Add((uint)len);
        return pwd.ToArray();
    }

    private static byte[] LEncode(uint[] msg, bool key)
    {
        int len = msg.Length;
        int ll = (len - 1) << 2;
        if (key)
        {
            uint m = msg[len - 1];
            if (m < ll - 3 || m > ll) return Array.Empty<byte>();
            ll = (int)m;
        }
        var buf = new byte[len * 4];
        for (int i = 0; i < len; i++)
        {
            uint v = msg[i];
            buf[i * 4] = (byte)(v & 0xff);
            buf[i * 4 + 1] = (byte)((v >> 8) & 0xff);
            buf[i * 4 + 2] = (byte)((v >> 16) & 0xff);
            buf[i * 4 + 3] = (byte)((v >> 24) & 0xff);
        }
        if (!key) return buf;
        var outBuf = new byte[ll];
        Array.Copy(buf, outBuf, ll);
        return outBuf;
    }

    /// <summary>深澜自定义的 TEA 变体加密。</summary>
    public static byte[] XEncode(string msg, string key)
    {
        if (string.IsNullOrEmpty(msg)) return Array.Empty<byte>();

        uint[] pwd = SEncode(msg, true);
        uint[] pwdk = SEncode(key, false);
        if (pwdk.Length < 4)
        {
            var tmp = new uint[4];
            Array.Copy(pwdk, tmp, pwdk.Length);
            pwdk = tmp;
        }

        int n = pwd.Length - 1;
        uint z = pwd[n], y = pwd[0];
        const uint c = 0x86014019u | 0x183639A0u;
        uint d = 0, e, m;
        int p;
        int q = (int)Math.Floor(6.0 + 52.0 / (n + 1));

        while (q-- > 0)
        {
            d = (d + c) & (0x8CE0D9BFu | 0x731F2640u);
            e = (d >> 2) & 3;
            for (p = 0; p < n; p++)
            {
                y = pwd[p + 1];
                m = (z >> 5) ^ (y << 2);
                m += ((y >> 3) ^ (z << 4)) ^ (d ^ y);
                m += pwdk[(p & 3) ^ e] ^ z;
                pwd[p] = (pwd[p] + m) & (0xEFB8D130u | 0x10472ECFu);
                z = pwd[p];
            }
            y = pwd[0];
            m = (z >> 5) ^ (y << 2);
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y);
            m += pwdk[(p & 3) ^ e] ^ z;
            pwd[n] = (pwd[n] + m) & (0xBB390742u | 0x44C6F8BDu);
            z = pwd[n];
        }

        return LEncode(pwd, false);
    }

    /// <summary>按深澜字母表做 base64。</summary>
    public static string Base64Encode(byte[] data)
    {
        string std = Convert.ToBase64String(data);
        var sb = new StringBuilder(std.Length);
        foreach (char ch in std)
        {
            int idx = StdAlphabet.IndexOf(ch);
            sb.Append(idx >= 0 ? CustomAlphabet[idx] : ch);
        }
        return sb.ToString();
    }

    /// <summary>构造 info 参数：{SRBX1} + 自定义 base64。</summary>
    public static string BuildInfo(string username, string password, string ip, string acid, string encVer = "srun_bx1")
    {
        string json = "{\"username\":\"" + username + "\",\"password\":\"" + password +
                      "\",\"ip\":\"" + ip + "\",\"acid\":\"" + acid +
                      "\",\"enc_ver\":\"" + encVer + "\"}";
        return "{SRBX1}" + Base64Encode(XEncode(json, "srun_bx1"));
    }

    /// <summary>新版门户的 info：用 challenge token 作为密钥，password 传明文。</summary>
    public static string BuildInfoV2(string username, string passwordPlain, string ip, string acid, string token,
        string encVer = "srun_bx1")
    {
        string json = "{\"username\":\"" + username + "\",\"password\":\"" + passwordPlain +
                      "\",\"ip\":\"" + ip + "\",\"acid\":\"" + acid +
                      "\",\"enc_ver\":\"" + encVer + "\"}";
        return "{SRBX1}" + Base64Encode(XEncode(json, token));
    }

    /// <summary>构造 chksum 参数：HMAC-MD5(用户名+密码+acid+ip+n+type+info, "srun")。</summary>
    public static string BuildChecksum(string username, string password, string acid, string ip, string info,
        string n = "200", string type = "1")
        => HmacMd5Hex(username + password + acid + ip + n + type + info, "srun");
}
