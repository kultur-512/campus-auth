using System.Net.Http;
using System.Text.Json;
using CampusAuth;

string baseUrl = args.Length > 0 ? args[0] : "http://127.0.0.1:8899";
int pass = 0, fail = 0;

void Check(string name, bool ok, string detail = "")
{
    if (ok) { pass++; Console.WriteLine($"  [PASS] {name}"); }
    else { fail++; Console.WriteLine($"  [FAIL] {name} {detail}"); }
}

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

async Task ResetMock()
{
    await http.GetStringAsync($"{baseUrl}/__mode?m=normal");
}

async Task<bool> MockLoggedIn()
{
    var s = await http.GetStringAsync($"{baseUrl}/__state");
    using var doc = JsonDocument.Parse(s);
    return doc.RootElement.GetProperty("logged_in").GetBoolean();
}

var cfg = new AppConfig
{
    Username = "20230001",
    Password = "Passw0rd!",
    PortalUrl = baseUrl,
    ProbeUrl = baseUrl + "/generate_204",
    AcId = 1,
    IntervalSeconds = 2,
    FailThreshold = 1,
    KeepAliveSeconds = 0
};

Console.WriteLine("== 守护循环：启动时处于断网状态，应自动完成认证 ==");
await ResetMock();
Check("初始状态：未登录", !await MockLoggedIn());

var states = new List<GuardState>();
using var guardian = new Guardian(cfg);
guardian.StateChanged += (s, m) =>
{
    states.Add(s);
    Console.WriteLine($"    状态 → {s}：{m}");
};

guardian.Start();

bool online = false;
for (int i = 0; i < 30; i++)
{
    await Task.Delay(500);
    if (guardian.State == GuardState.Online) { online = true; break; }
}

Check("守护进入「网络正常」状态", online, "→ 当前 " + guardian.State);
Check("模拟门户记录到登录成功", await MockLoggedIn());
Check("状态序列包含 断网→认证中→在线",
    states.Contains(GuardState.Offline) && states.Contains(GuardState.LoggingIn) && states.Contains(GuardState.Online),
    "→ " + string.Join(",", states));

Console.WriteLine();
Console.WriteLine("== 暂停 / 恢复 ==");
guardian.Pause();
await Task.Delay(300);
Check("暂停后状态为 Paused", guardian.State == GuardState.Paused, "→ " + guardian.State);
guardian.Resume();
await Task.Delay(2500);
Check("恢复后重新检测到在线", guardian.State == GuardState.Online, "→ " + guardian.State);

Console.WriteLine();
Console.WriteLine("== 掉线后自动重连 ==");
await ResetMock();                     // 模拟会话被踢下线
await Task.Delay(6000);                // 等守护发现并重新认证
Check("重新认证成功", await MockLoggedIn());
Check("状态回到在线", guardian.State == GuardState.Online, "→ " + guardian.State);

guardian.Stop();
Console.WriteLine();
Console.WriteLine($"结果：通过 {pass}，失败 {fail}");
return fail == 0 ? 0 : 1;
