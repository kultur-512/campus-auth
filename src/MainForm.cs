using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CampusAuth;

public class MainForm : Form
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "CampusAuth";

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);

    /// <summary>按颜色缓存托盘图标，避免反复创建 HICON 把 GDI 句柄耗光。</summary>
    private static readonly Dictionary<int, Icon> IconCache = new();

    private readonly AppConfig _cfg;
    private readonly Guardian _guardian;
    private readonly SrunClient _diag = new();
    private readonly bool _startHidden;
    private readonly EventWaitHandle? _showSignal;

    // 控件
    private readonly Ui.HeaderPanel _header = new();
    private readonly TextBox _txtUser = new();
    private readonly TextBox _txtPass = new();
    private readonly TextBox _txtPortal = new();
    private readonly CheckBox _chkShowPass = new();
    private readonly NumericUpDown _numInterval = new();
    private readonly NumericUpDown _numThreshold = new();
    private readonly CheckBox _chkAutoStart = new();
    private readonly CheckBox _chkTray = new();
    private readonly CheckBox _chkAutoRun = new();
    private readonly RichTextBox _log = new();
    private readonly Ui.FlatButton _btnStart = new();
    private readonly Ui.FlatButton _btnStop = new();
    private readonly Ui.FlatButton _btnNow = new();
    private readonly Ui.FlatButton _btnDiag = new();
    private readonly Ui.FlatButton _btnDetect = new();
    private readonly Ui.FlatButton _btnClearLog = new();
    private readonly Ui.FlatButton _btnOpenLog = new();
    private readonly System.Windows.Forms.Timer _tick = new();

    private Ui.Card? _cardLog;
    private NotifyIcon? _tray;
    private ToolStripMenuItem? _miPause;
    private ToolStripMenuItem? _miAutoStart;
    private ToolStripMenuItem? _miStatus;

    private GuardState _state = GuardState.Stopped;
    private Color _trayIconColor = Color.Empty;
    private string _detail = "";
    private bool _suppressAutoStartEvent;

    public MainForm(bool startHidden = false, EventWaitHandle? showSignal = null)
    {
        _startHidden = startHidden;
        _showSignal = showSignal;
        _cfg = AppConfig.Load();
        _guardian = new Guardian(_cfg);

        AutoScaleMode = AutoScaleMode.None;

        Text = "校园网自动认证";
        ClientSize = new Size(640, 764);
        MinimumSize = new Size(600, 700);
        StartPosition = FormStartPosition.CenterScreen;
        Font = Ui.Font(9F);
        BackColor = Palette.Bg;
        DoubleBuffered = true;
        Icon = MakeIcon(Palette.Primary);

        BuildUi();
        ApplyDpiScale();
        RestoreWindowSize();
        LoadToUi();
        SetupTray();

        _guardian.StateChanged += OnStateChanged;
        _guardian.LoginSucceeded += OnLoginSucceeded;
        _guardian.Notify += OnNotify;
        Log.Written += OnLogWritten;

        _tick.Interval = 1000;
        _tick.Tick += (_, _) => { UpdateStats(); CheckResourceUsage(); };
        _tick.Start();

        Log.Cleanup();
        Log.Info("程序启动 · " + Application.ProductVersion + " · " + AppConfig.ConfigPath);

        if (_showSignal != null) StartShowListener();

        if (_cfg.AutoRun && !string.IsNullOrWhiteSpace(_cfg.Username) && !string.IsNullOrWhiteSpace(_cfg.Password))
            StartGuard();
        else
            SetIdle();
    }

    // ---------------- 界面构建 ----------------

    private void BuildUi()
    {
        _header.Location = new Point(24, 20);
        _header.Size = new Size(592, 108);
        _header.SetStatus("未启动", "填写账号密码后点「开始守护」", Color.Gray);
        _header.SetStats("--", "0");

        // --- 账号卡片 ---
        var cardAccount = new Ui.Card { Title = "账号", Location = new Point(24, 144), Size = new Size(592, 152) };
        cardAccount.Controls.Add(Label("账号", 16, 48));
        StyleInput(_txtUser, 72, 44, 296);
        cardAccount.Controls.Add(_txtUser);

        cardAccount.Controls.Add(Label("密码", 16, 84));
        StyleInput(_txtPass, 72, 80, 296);
        _txtPass.UseSystemPasswordChar = true;
        cardAccount.Controls.Add(_txtPass);

        _chkShowPass.Text = "显示";
        _chkShowPass.AutoSize = false;
        _chkShowPass.Size = new Size(56, 22);
        _chkShowPass.BackColor = Color.Transparent;
        _chkShowPass.ForeColor = Palette.Muted;
        _chkShowPass.Location = new Point(378, 84);
        _chkShowPass.CheckedChanged += (_, _) => _txtPass.UseSystemPasswordChar = !_chkShowPass.Checked;
        cardAccount.Controls.Add(_chkShowPass);

        cardAccount.Controls.Add(Label("门户", 16, 120));
        StyleInput(_txtPortal, 72, 116, 296);
        _txtPortal.PlaceholderText = "留空自动探测";
        cardAccount.Controls.Add(_txtPortal);

        StyleButton(_btnDetect, "自动探测", 378, 114, 96, 30);
        _btnDetect.Click += async (_, _) => await DetectPortalAsync();
        cardAccount.Controls.Add(_btnDetect);

        // --- 选项卡片 ---
        var cardOpt = new Ui.Card { Title = "选项", Location = new Point(24, 308), Size = new Size(592, 118) };
        cardOpt.Controls.Add(Label("检测间隔", 16, 46));
        _numInterval.Minimum = 2;
        _numInterval.Maximum = 600;
        _numInterval.Location = new Point(84, 42);
        _numInterval.Size = new Size(70, 26);
        _numInterval.BackColor = Color.White;
        _numInterval.ForeColor = Palette.Text;
        cardOpt.Controls.Add(_numInterval);
        cardOpt.Controls.Add(Label("秒", 160, 46));

        cardOpt.Controls.Add(Label("连续失败", 190, 46));
        _numThreshold.Minimum = 1;
        _numThreshold.Maximum = 10;
        _numThreshold.Location = new Point(246, 42);
        _numThreshold.Size = new Size(60, 26);
        _numThreshold.BackColor = Color.White;
        _numThreshold.ForeColor = Palette.Text;
        cardOpt.Controls.Add(_numThreshold);
        cardOpt.Controls.Add(Label("次判定掉线", 312, 46));

        _chkAutoStart.Text = "开机自启";
        _chkAutoStart.Location = new Point(16, 82);
        _chkAutoStart.AutoSize = false;
        _chkAutoStart.Size = new Size(88, 22);
        _chkAutoStart.BackColor = Color.Transparent;
        _chkAutoStart.ForeColor = Palette.Text;
        _chkAutoStart.CheckedChanged += (_, _) => { if (!_suppressAutoStartEvent) ApplyAutoStart(_chkAutoStart.Checked); };

        _chkTray.Text = "关闭时最小化到托盘";
        _chkTray.Location = new Point(118, 82);
        _chkTray.AutoSize = false;
        _chkTray.Size = new Size(152, 22);
        _chkTray.BackColor = Color.Transparent;
        _chkTray.ForeColor = Palette.Text;

        _chkAutoRun.Text = "启动后自动守护";
        _chkAutoRun.Location = new Point(286, 82);
        _chkAutoRun.AutoSize = false;
        _chkAutoRun.Size = new Size(136, 22);
        _chkAutoRun.BackColor = Color.Transparent;
        _chkAutoRun.ForeColor = Palette.Text;

        cardOpt.Controls.AddRange(new Control[] { _chkAutoStart, _chkTray, _chkAutoRun });

        // --- 操作按钮 ---
        StyleButton(_btnStart, "开始守护", 24, 442, 120, 40, primary: true);
        _btnStart.Click += (_, _) => StartGuard();

        StyleButton(_btnStop, "停止", 152, 442, 84, 40);
        _btnStop.Enabled = false;
        _btnStop.Click += (_, _) => StopGuard();

        StyleButton(_btnNow, "立即认证", 244, 442, 104, 40);
        _btnNow.Click += async (_, _) => await CheckNowAsync();

        StyleButton(_btnDiag, "诊断", 532, 442, 84, 40);
        _btnDiag.Click += async (_, _) => await DiagnoseAsync();

        // --- 日志卡片 ---
        var cardLog = new Ui.Card { Title = "运行日志", Location = new Point(24, 498), Size = new Size(592, 250) };
        _cardLog = cardLog;

        StyleButton(_btnClearLog, "清空", 410, 10, 58, 26, small: true);
        _btnClearLog.Click += (_, _) => _log.Clear();
        StyleButton(_btnOpenLog, "日志目录", 476, 10, 84, 26, small: true);
        _btnOpenLog.Click += (_, _) => OpenLogFolder();

        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.BorderStyle = BorderStyle.None;
        _log.BackColor = Color.White;
        _log.ForeColor = Color.FromArgb(60, 68, 80);
        _log.Font = new Font("Consolas", 8.5F);
        _log.ScrollBars = RichTextBoxScrollBars.Vertical;
        _log.DetectUrls = false;
        _log.Location = new Point(16, 46);
        _log.Size = new Size(560, 188);
        _log.WordWrap = true;

        cardLog.Controls.AddRange(new Control[] { _btnClearLog, _btnOpenLog, _log });

        Controls.AddRange(new Control[]
        {
            cardLog, _btnDiag, _btnNow, _btnStop, _btnStart, cardOpt, cardAccount, _header
        });
    }

    private static Label Label(string text, int x, int y) => new()
    {
        Text = text,
        Location = new Point(x, y + 2),
        AutoSize = true,
        BackColor = Color.Transparent,
        ForeColor = Palette.Text
    };

    private static void StyleInput(TextBox tb, int x, int y, int w)
    {
        tb.Location = new Point(x, y);
        tb.Size = new Size(w, 26);
        tb.BorderStyle = BorderStyle.FixedSingle;
        tb.ForeColor = Palette.Text;
    }

    private static void StyleButton(Ui.FlatButton b, string text, int x, int y, int w, int h,
        bool primary = false, bool small = false)
    {
        b.Text = text;
        b.Location = new Point(x, y);
        b.Size = new Size(w, h);
        b.Font = Ui.Font(small ? 8.5F : 9.5F, FontStyle.Bold);
        if (primary)
        {
            b.Normal = Palette.Primary;
            b.Hover = Palette.PrimaryHover;
            b.Down = Palette.PrimaryDown;
            b.TextColor = Color.White;
        }
        else
        {
            b.Normal = Palette.Ghost;
            b.Hover = Palette.GhostHover;
            b.Down = Palette.GhostDown;
            b.TextColor = Palette.Text;
        }
    }

    private void SetupTray()
    {
        _tray = new NotifyIcon
        {
            Icon = MakeIcon(Color.Gray),
            Visible = true,
            Text = "校园网自动认证"
        };
        _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) ShowMain(); };

        var menu = new ContextMenuStrip { ShowImageMargin = false };

        _miStatus = new ToolStripMenuItem("未启动") { Enabled = false };
        _miPause = new ToolStripMenuItem("暂停自动认证", null, (_, _) => TogglePause());
        _miAutoStart = new ToolStripMenuItem("开机自启", null, (_, _) => ToggleAutoStart())
        {
            CheckOnClick = false,
            Checked = IsAutoStartEnabled()
        };

        menu.Items.Add(_miStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("打开主界面", null, (_, _) => ShowMain()));
        menu.Items.Add(new ToolStripMenuItem("立即检测并认证", null, async (_, _) => await CheckNowAsync()));
        menu.Items.Add(_miPause);
        menu.Items.Add(_miAutoStart);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("打开日志目录", null, (_, _) => OpenLogFolder()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("退出", null, (_, _) => ExitApp()));

        _tray.ContextMenuStrip = menu;
    }

    private void StartShowListener()
    {
        var th = new Thread(() =>
        {
            while (true)
            {
                try
                {
                    if (_showSignal!.WaitOne(TimeSpan.FromSeconds(1)))
                    {
                        if (IsDisposed) return;
                        BeginInvoke(new Action(ShowMain));
                    }
                }
                catch { return; }
            }
        }) { IsBackground = true };
        th.Start();
    }

    // ---------------- 状态 ----------------

    private void SetIdle()
    {
        _state = GuardState.Stopped;
        _detail = "填写账号密码后点「开始守护」";
        _header.SetStatus("未启动", _detail, Color.Gray);
        ApplyStateToUi(GuardState.Stopped);
    }

    private void OnStateChanged(GuardState state, string message)
    {
        if (IsDisposed) return;
        if (IsHandleCreated && InvokeRequired)
        {
            BeginInvoke(new Action(() => OnStateChanged(state, message)));
            return;
        }

        try
        {
            RefreshState(state, message);
        }
        catch (Exception ex)
        {
            Log.Warn("刷新界面失败：" + ex.Message);
        }
    }

    private void RefreshState(GuardState state, string message)
    {
        _state = state;
        _detail = message;

        (string text, Color color) = state switch
        {
            GuardState.Online => ("网络正常", Palette.Success),
            GuardState.Offline => ("网络已断开", Palette.Warn),
            GuardState.LoggingIn => ("正在认证", Palette.Info),
            GuardState.Checking => ("检测中", Color.FromArgb(120, 138, 165)),
            GuardState.Paused => ("已暂停", Color.FromArgb(150, 156, 168)),
            GuardState.Error => ("认证失败", Palette.Danger),
            _ => ("未启动", Color.Gray)
        };

        _header.SetStatus(text, message, color);
        ApplyStateToUi(state);
        UpdateStats();

        if (_tray != null)
        {
            if (_trayIconColor != color)
            {
                _trayIconColor = color;
                _tray.Icon = MakeIcon(color);
            }
            _tray.Text = "校园网自动认证 · " + text;
        }
        if (_miStatus != null) _miStatus.Text = text + " · " + message;
    }

    private void ApplyStateToUi(GuardState state)
    {
        bool running = state is not (GuardState.Stopped or GuardState.Paused);
        _btnStart.Enabled = state is GuardState.Stopped or GuardState.Paused;
        _btnStop.Enabled = running || state == GuardState.Paused;
        if (_miPause != null)
            _miPause.Text = state == GuardState.Paused ? "恢复自动认证" : "暂停自动认证";
    }

    private DateTime _lastResCheck = DateTime.MinValue;

    /// <summary>定期检查 GDI/USER 句柄数，防止再出现画不出界面的情况。</summary>
    private void CheckResourceUsage()
    {
        if ((DateTime.Now - _lastResCheck).TotalMinutes < 10) return;
        _lastResCheck = DateTime.Now;
        try
        {
            using var proc = Process.GetCurrentProcess();
            uint gdi = GetGuiResources(proc.Handle, 0);
            uint user = GetGuiResources(proc.Handle, 1);
            Log.Debug($"资源占用 GDI={gdi} USER={user}");
            if (gdi > 6000 || user > 6000)
                Log.Warn($"GDI/USER 句柄偏高（GDI={gdi} USER={user}），可能存在资源泄漏");
        }
        catch { }
    }

    private void UpdateStats()
    {
        string uptime = "--";
        if (_guardian.State == GuardState.Online && _guardian.OnlineSince is { } since)
        {
            var span = DateTime.Now - since;
            uptime = span.TotalHours >= 1
                ? $"{(int)span.TotalHours}时{span.Minutes:00}分"
                : $"{span.Minutes:00}:{span.Seconds:00}";
        }
        _header.SetStats(uptime, _guardian.LoginCount.ToString());
    }

    private void OnLoginSucceeded(string message)
    {
        _tray?.ShowBalloonTip(2500, "认证成功", "校园网已连接", ToolTipIcon.Info);
    }

    private void OnNotify(string message, bool isError)
    {
        if (IsDisposed) return;
        if (IsHandleCreated && InvokeRequired) { BeginInvoke(new Action(() => OnNotify(message, isError))); return; }
        _tray?.ShowBalloonTip(4000, isError ? "需要注意" : "提示", message,
            isError ? ToolTipIcon.Warning : ToolTipIcon.Info);
    }

    private void OnLogWritten(LogLevel level, string line)
    {
        if (IsDisposed) return;
        if (IsHandleCreated && InvokeRequired)
        {
            BeginInvoke(new Action(() => OnLogWritten(level, line)));
            return;
        }

        if (_log.TextLength > 120_000) _log.Clear();

        Color color = level switch
        {
            LogLevel.Error => Color.FromArgb(214, 62, 52),
            LogLevel.Warn => Color.FromArgb(190, 118, 10),
            LogLevel.Debug => Color.FromArgb(150, 158, 170),
            _ => Color.FromArgb(60, 68, 80)
        };

        _log.SelectionStart = _log.TextLength;
        _log.SelectionLength = 0;
        _log.SelectionColor = color;
        _log.AppendText(line + Environment.NewLine);
        _log.SelectionColor = _log.ForeColor;
        _log.ScrollToCaret();
    }

    // ---------------- 配置读写 ----------------

    private void LoadToUi()
    {
        _txtUser.Text = _cfg.Username;
        _txtPass.Text = _cfg.Password;
        _txtPortal.Text = _cfg.PortalUrl;
        _numInterval.Value = Math.Clamp(_cfg.IntervalSeconds, 2, 600);
        _numThreshold.Value = Math.Clamp(_cfg.FailThreshold, 1, 10);

        _suppressAutoStartEvent = true;
        _chkAutoStart.Checked = IsAutoStartEnabled();
        _suppressAutoStartEvent = false;

        _chkTray.Checked = _cfg.MinimizeToTray;
        _chkAutoRun.Checked = _cfg.AutoRun;
    }

    private bool SaveFromUi(bool quiet = false)
    {
        if (string.IsNullOrWhiteSpace(_txtUser.Text) || string.IsNullOrWhiteSpace(_txtPass.Text))
        {
            if (!quiet)
                MessageBox.Show(this, "请先填写账号和密码。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return false;
        }

        _cfg.Username = _txtUser.Text.Trim();
        _cfg.Password = _txtPass.Text;
        _cfg.PortalUrl = NormalizePortal(_txtPortal.Text.Trim());
        _cfg.IntervalSeconds = (int)_numInterval.Value;
        _cfg.FailThreshold = (int)_numThreshold.Value;
        _cfg.MinimizeToTray = _chkTray.Checked;
        _cfg.AutoRun = _chkAutoRun.Checked;
        _cfg.Save();
        _guardian.UpdateConfig(_cfg);
        return true;
    }

    /// <summary>允许用户只填 IP 或带路径的认证页地址，统一成 http://host[:port]。</summary>
    private static string NormalizePortal(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "";
        input = input.Trim();
        if (!input.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            input = "http://" + input;
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri)) return "";
        return uri.IsDefaultPort ? $"{uri.Scheme}://{uri.Host}" : $"{uri.Scheme}://{uri.Host}:{uri.Port}";
    }

    // ---------------- 操作 ----------------

    private void StartGuard()
    {
        if (!SaveFromUi()) return;
        _guardian.Start();
        _btnStart.Enabled = false;
        _btnStop.Enabled = true;
    }

    private void StopGuard()
    {
        _guardian.Stop();
        _btnStart.Enabled = true;
        _btnStop.Enabled = false;
    }

    private async Task CheckNowAsync()
    {
        if (!SaveFromUi()) return;
        if (_state is GuardState.Stopped or GuardState.Paused) _guardian.Start();
        await _guardian.CheckNowAsync();
    }

    private void TogglePause()
    {
        if (_guardian.IsPaused)
        {
            _guardian.Resume();
        }
        else
        {
            _guardian.Pause();
        }
        ApplyStateToUi(_guardian.IsPaused ? GuardState.Paused : _guardian.State);
    }

    private async Task DetectPortalAsync()
    {
        _btnDetect.Enabled = false;
        _btnDetect.Text = "探测中…";
        try
        {
            Log.Info("—— 手动探测门户 ——");
            var portal = await _diag.DiscoverPortalAsync();
            if (portal == null)
            {
                Log.Warn("未探测到门户");
                MessageBox.Show(this,
                    "没探测到认证门户。\n\n可能原因：\n1. 当前已联网（未认证时才会跳转门户）\n2. 门户不是深澜系统\n\n可以断网后重试，或直接填写门户 IP。",
                    "探测结果", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _txtPortal.Text = portal;
            var st = await _diag.QueryStatusAsync(portal);
            Log.Info($"门户 {portal} · 在线={st.Online} 用户={st.UserName} IP={st.Ip} ac_id={st.AcId}");
            if (int.TryParse(st.AcId, out int ac) && ac > 0) _cfg.AcId = ac;
        }
        finally
        {
            _btnDetect.Enabled = true;
            _btnDetect.Text = "自动探测";
        }
    }

    private async Task DiagnoseAsync()
    {
        _btnDiag.Enabled = false;
        try
        {
            Log.Info("—— 诊断开始 ——");
            Log.Info("联网检测：" + (await _diag.IsInternetOkAsync() ? "可以上网" : "不能上网（需要认证）"));

            string portal = NormalizePortal(_txtPortal.Text.Trim());
            if (portal.Length == 0)
            {
                var found = await _diag.DiscoverPortalAsync();
                if (found != null) { portal = found; _txtPortal.Text = found; }
            }

            if (portal.Length > 0)
            {
                Log.Info("本机 IP（通往门户）：" + SrunClient.GetLocalIp(portal));
                var st = await _diag.QueryStatusAsync(portal);
                Log.Info($"门户状态：在线={st.Online} 用户={st.UserName} IP={st.Ip} ac_id={st.AcId}");
                if (!st.Online && st.Raw.Length > 0) Log.Info("门户原始返回：" + st.Raw);
                if (int.TryParse(st.AcId, out int ac) && ac > 0) _cfg.AcId = ac;
            }
            else
            {
                Log.Warn("没有门户地址，无法查询状态");
            }
            Log.Info("—— 诊断结束 ——");
        }
        finally
        {
            _btnDiag.Enabled = true;
        }
    }

    // ---------------- 窗口 / 托盘 ----------------

    private void ShowMain()
    {
        ShowInTaskbar = true;
        Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
        BringToFront();
    }

    private void OpenLogFolder()
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", AppConfig.ConfigDir) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Log.Warn("打开日志目录失败：" + ex.Message);
        }
    }

    private void ExitApp()
    {
        if (_tray != null) _tray.Visible = false;
        _guardian.Dispose();
        Application.Exit();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        if (_startHidden)
        {
            ShowInTaskbar = false;
            Hide();
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        SaveWindowSize();

        if (e.CloseReason == CloseReason.UserClosing && _chkTray.Checked)
        {
            e.Cancel = true;
            Hide();
            ShowInTaskbar = false;
            _tray?.ShowBalloonTip(2000, "校园网自动认证", "仍在后台守护，双击托盘图标可打开。", ToolTipIcon.Info);
            return;
        }

        if (_tray != null) _tray.Visible = false;
        _guardian.Dispose();
        base.OnFormClosing(e);
    }

    /// <summary>按屏幕 DPI 等比放大整个界面（设计稿是 96 DPI）。</summary>
    private void ApplyDpiScale()
    {
        float s;
        using (var g = Graphics.FromHwnd(IntPtr.Zero)) s = g.DpiX / 96f;
        if (Math.Abs(s - 1f) < 0.01f) return;

        ClientSize = new Size((int)Math.Round(ClientSize.Width * s), (int)Math.Round(ClientSize.Height * s));
        MinimumSize = new Size((int)Math.Round(MinimumSize.Width * s), (int)Math.Round(MinimumSize.Height * s));
        ScaleChildren(this, s);
        FitToScreen();
    }

    /// <summary>窗口比屏幕还高时，压缩日志区而不是让窗口跑出屏幕。</summary>
    private void FitToScreen()
    {
        var wa = Screen.FromControl(this).WorkingArea;
        int maxHeight = wa.Height - 40;
        if (ClientSize.Height <= maxHeight || _cardLog == null) return;

        int overflow = ClientSize.Height - maxHeight;
        int newLogHeight = Math.Max(120, _cardLog.Height - overflow);
        int shrink = _cardLog.Height - newLogHeight;
        _cardLog.Height = newLogHeight;
        _log.Size = new Size(_cardLog.Width - 32, Math.Max(40, _cardLog.Height - 62));
        ClientSize = new Size(ClientSize.Width, ClientSize.Height - shrink);
        MinimumSize = new Size(MinimumSize.Width, Math.Min(MinimumSize.Height, ClientSize.Height));
    }

    private static void ScaleChildren(Control parent, float s)
    {
        foreach (Control c in parent.Controls)
        {
            c.Location = new Point((int)Math.Round(c.Left * s), (int)Math.Round(c.Top * s));
            c.Size = new Size((int)Math.Round(c.Width * s), (int)Math.Round(c.Height * s));
            ScaleChildren(c, s);
        }
    }

    private void RestoreWindowSize()
    {
        if (_cfg.WindowWidth > 0 && _cfg.WindowHeight > 0 &&
            _cfg.WindowWidth >= MinimumSize.Width && _cfg.WindowHeight >= MinimumSize.Height)
            ClientSize = new Size(_cfg.WindowWidth, _cfg.WindowHeight);
    }

    private void SaveWindowSize()
    {
        if (WindowState == FormWindowState.Normal)
        {
            _cfg.WindowWidth = ClientSize.Width;
            _cfg.WindowHeight = ClientSize.Height;
            _cfg.Save();
        }
    }

    // ---------------- 开机自启 ----------------

    private static bool IsAutoStartEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(RunValue) != null;
        }
        catch { return false; }
    }

    private void ToggleAutoStart()
    {
        bool enable = !IsAutoStartEnabled();
        ApplyAutoStart(enable);
        _suppressAutoStartEvent = true;
        _chkAutoStart.Checked = enable;
        _suppressAutoStartEvent = false;
        if (_miAutoStart != null) _miAutoStart.Checked = enable;
    }

    private void ApplyAutoStart(bool enable)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, true);
            if (key == null) return;
            if (enable)
            {
                string exe = Environment.ProcessPath ?? Application.ExecutablePath;
                key.SetValue(RunValue, "\"" + exe + "\" --min");
            }
            else
            {
                key.DeleteValue(RunValue, false);
            }
            if (_miAutoStart != null) _miAutoStart.Checked = enable;
            Log.Info("开机自启：" + (enable ? "已开启" : "已关闭"));
        }
        catch (Exception ex)
        {
            Log.Warn("设置开机自启失败：" + ex.Message);
        }
    }

    // ---------------- 图标 ----------------

    private static Icon MakeIcon(Color color)
    {
        int key = color.ToArgb();
        if (IconCache.TryGetValue(key, out var cached)) return cached;

        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            using var brush = new SolidBrush(color);
            g.FillEllipse(brush, 1, 1, 30, 30);
            using var pen = new Pen(Color.White, 3.2f)
            {
                StartCap = System.Drawing.Drawing2D.LineCap.Round,
                EndCap = System.Drawing.Drawing2D.LineCap.Round
            };
            g.DrawArc(pen, 8, 11, 16, 16, 200, 140);
            g.DrawArc(pen, 11.5f, 15, 9, 9, 200, 140);
            using var dotBrush = new SolidBrush(Color.White);
            g.FillEllipse(dotBrush, 14.2f, 22.2f, 3.6f, 3.6f);
        }

        // GetHicon 得到的句柄必须手动销毁，否则每次调用都会泄漏一个 USER/GDI 对象
        IntPtr handle = bmp.GetHicon();
        Icon icon;
        try
        {
            using var tmp = Icon.FromHandle(handle);
            icon = (Icon)tmp.Clone();      // Clone 之后才能安全销毁原句柄
        }
        finally
        {
            DestroyIcon(handle);
        }

        IconCache[key] = icon;
        return icon;
    }
}
