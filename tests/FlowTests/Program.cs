using System.Net.Http;
using CampusAuth;

string baseUrl = args.Length > 0 ? args[0] : "http://127.0.0.1:8899";
int pass = 0, fail = 0;

void Check(string name, bool ok, string detail = "")
{
    if (ok) { pass++; Console.WriteLine($"  [PASS] {name}"); }
    else { fail++; Console.WriteLine($"  [FAIL] {name} {detail}"); }
}

async Task SetMode(string mode)
{
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    await http.GetStringAsync($"{baseUrl}/__mode?m={mode}");
}

using var client = new SrunClient();

Console.WriteLine("== 场景 1：账号密码正确，应认证成功 ==");
await SetMode("normal");
var r1 = await client.LoginAsync(baseUrl, "20230001", "Passw0rd!", 1);
Check("认证成功", r1.Success, "→ " + r1.Message);

Console.WriteLine();
Console.WriteLine("== 场景 2：密码错误，应返回失败 ==");
await SetMode("normal");
var r2 = await client.LoginAsync(baseUrl, "20230001", "WrongPass", 1);
Check("认证失败", !r2.Success, "→ " + r2.Message);
Check("带回了失败原因", r2.Message.Length > 0, "→ " + r2.Message);

Console.WriteLine();
Console.WriteLine("== 场景 3：门户没有 get_challenge（老版协议），应走老版签名 ==");
await SetMode("no_challenge");
var r3a = await client.LoginAsync(baseUrl, "20230001", "Passw0rd!", 1);
Check("老版协议认证成功", r3a.Success, "→ " + r3a.Message);

Console.WriteLine();
Console.WriteLine("== 场景 4：门户连 srun_portal 都不支持（404），应回退 do_login ==");
await SetMode("reject_srun");
var r3 = await client.LoginAsync(baseUrl, "20230001", "Passw0rd!", 1);
Check("回退后成功", r3.Success, "→ " + r3.Message);

Console.WriteLine();
Console.WriteLine("== 场景 5：状态查询与 ac_id 探测 ==");
await SetMode("normal");
var st1 = await client.QueryStatusAsync(baseUrl);
Check("未登录时状态为离线", !st1.Online, "→ " + st1.Raw);
await client.LoginAsync(baseUrl, "20230001", "Passw0rd!", 1);
var st2 = await client.QueryStatusAsync(baseUrl);
Check("登录后状态为在线", st2.Online, "→ " + st2.Raw);
Check("能读到用户名", st2.UserName == "20230001", "→ " + st2.UserName);
string acid = await client.DiscoverAcIdAsync(baseUrl);
Check("能解析 ac_id", acid == "1", "→ " + acid);

Console.WriteLine();
Console.WriteLine("== 场景 5：门户地址校验 ==");
Check("合法门户被识别", await client.ValidatePortalAsync(baseUrl));
Check("乱填地址被拒绝", !await client.ValidatePortalAsync("http://127.0.0.1:1"));

Console.WriteLine();
Console.WriteLine($"结果：通过 {pass}，失败 {fail}");
return fail == 0 ? 0 : 1;
