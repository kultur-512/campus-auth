using CampusAuth;

// 用法：SetupConfig <账号> <密码> [门户] [ac_id]
string user = args.Length > 0 ? args[0] : "";
string pass = args.Length > 1 ? args[1] : "";
string portal = args.Length > 2 ? args[2] : "";
int acid = args.Length > 3 ? int.Parse(args[3]) : 1;

var cfg = AppConfig.Load();
cfg.Username = user;
cfg.Password = pass;
cfg.PortalUrl = portal;
cfg.AcId = acid;
cfg.AutoRun = true;
cfg.MinimizeToTray = true;
cfg.IntervalSeconds = 5;
cfg.FailThreshold = 2;
cfg.KeepAliveSeconds = 300;
cfg.Save();

Console.WriteLine("已写入 " + AppConfig.ConfigPath);
Console.WriteLine($"  账号：{cfg.Username}");
Console.WriteLine($"  密码：{new string('*', cfg.Password.Length)}（{cfg.Password.Length} 位，加密存储）");
Console.WriteLine($"  门户：{cfg.PortalUrl}  ac_id={cfg.AcId}");
Console.WriteLine("  回读密码是否正确：" + (cfg.Password == pass));
return 0;
