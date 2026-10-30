using CampusAuth;

// 用法：LiveTest <portal> <username> <password> [ac_id]
string portal = args.Length > 0 ? args[0] : "http://172.16.154.130";
string user = args.Length > 1 ? args[1] : "";
string pass = args.Length > 2 ? args[2] : "";
int acid = args.Length > 3 ? int.Parse(args[3]) : 1;

Log.Written += (_, line) => Console.WriteLine("  " + line);

using var client = new SrunClient();

Console.WriteLine($"门户：{portal}");
Console.WriteLine("联网检测：" + (await client.IsInternetOkAsync() ? "能上网" : "不能上网"));
Console.WriteLine("本机 IP（通往门户）：" + SrunClient.GetLocalIp(portal));
Console.WriteLine("门户校验：" + (await client.ValidatePortalAsync(portal) ? "是深澜门户" : "不像深澜门户"));

var st = await client.QueryStatusAsync(portal);
Console.WriteLine($"当前状态：在线={st.Online} 用户={st.UserName} IP={st.Ip} ac_id={st.AcId}");

Console.WriteLine();
Console.WriteLine("== 执行认证 ==");
var r = await client.LoginAsync(portal, user, pass, acid);
Console.WriteLine($"结果：{(r.Success ? "成功" : "失败")}  {r.Message}");

Console.WriteLine();
await Task.Delay(1500);
var st2 = await client.QueryStatusAsync(portal);
Console.WriteLine($"认证后状态：在线={st2.Online} 用户={st2.UserName} IP={st2.Ip}");
Console.WriteLine("联网检测：" + (await client.IsInternetOkAsync() ? "能上网" : "不能上网"));

return r.Success && st2.Online ? 0 : 1;
