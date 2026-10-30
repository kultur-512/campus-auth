using System.Net.NetworkInformation;

namespace CampusAuth;

public enum GuardState
{
    Stopped,
    Checking,
    Online,
    Offline,
    LoggingIn,
    Paused,
    Error
}

/// <summary>守护进程：周期性检测网络，掉线即自动认证。</summary>
public class Guardian : IDisposable
{
    private readonly SrunClient _client = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private AppConfig _cfg;
    private string? _portal;
    private int _failCount;
    private DateTime _lastKeepAlive = DateTime.MinValue;
    private DateTime _lastFallback = DateTime.MinValue;
    private DateTime _credentialCooldownUntil = DateTime.MinValue;
    private int _loginFailStreak;
    private int _loginCount;
    private string _lastLoginMessage = "";
    private volatile bool _paused;
    private volatile bool _loginInProgress;
    private readonly SemaphoreSlim _wake = new(0, 1);

    public event Action<GuardState, string>? StateChanged;
    /// <summary>成功认证一次触发</summary>
    public event Action<string>? LoginSucceeded;
    /// <summary>需要提示用户时触发（消息, 是否为错误）</summary>
    public event Action<string, bool>? Notify;

    public GuardState State { get; private set; } = GuardState.Stopped;
    public string? Portal => _portal;
    public DateTime? OnlineSince { get; private set; }
    /// <summary>本次运行累计认证成功次数</summary>
    public int LoginCount => _loginCount;

    public Guardian(AppConfig cfg)
    {
        _cfg = cfg;
        _client.CustomProbeUrl = cfg.ProbeUrl;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkChanged;
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        Microsoft.Win32.SystemEvents.PowerModeChanged += OnPowerModeChanged;
    }

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        // 网络状态变化时立刻唤醒检测，不用等下一个周期
        Wake();
    }

    private void OnPowerModeChanged(object? sender, Microsoft.Win32.PowerModeChangedEventArgs e)
    {
        if (e.Mode == Microsoft.Win32.PowerModes.Resume)
        {
            Log.Info("系统已从休眠恢复，稍后重新检测网络");
            // 网卡起来需要一点时间
            Task.Run(async () => { await Task.Delay(4000); Wake(); });
        }
    }

    private void Wake()
    {
        try { _wake.Release(); } catch (SemaphoreFullException) { }
    }

    public void UpdateConfig(AppConfig cfg)
    {
        _cfg = cfg;
        _client.CustomProbeUrl = cfg.ProbeUrl;
    }

    public void Start()
    {
        if (_loop is { IsCompleted: false }) return;
        _cts = new CancellationTokenSource();
        _paused = false;
        _failCount = 0;
        if (!string.IsNullOrWhiteSpace(_cfg.PortalUrl)) _portal = _cfg.PortalUrl.TrimEnd('/');
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        Log.Info("守护已启动，检测间隔 " + _cfg.IntervalSeconds + " 秒");
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        _cts?.Dispose();
        _cts = null;
        SetState(GuardState.Stopped, "已停止");
        Log.Info("守护已停止");
    }

    public void Pause()
    {
        _paused = true;
        SetState(GuardState.Paused, "已暂停（不自动认证）");
        Log.Info("已暂停自动认证");
    }

    public void Resume()
    {
        _paused = false;
        Log.Info("已恢复自动认证");
        try { _wake.Release(); } catch (SemaphoreFullException) { }
    }

    public bool IsPaused => _paused;

    /// <summary>立即检测并（必要时）认证一次。</summary>
    public async Task CheckNowAsync()
    {
        if (_loginInProgress) return;
        await CheckOnceAsync(CancellationToken.None);
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!_paused && !_loginInProgress)
                {
                    await CheckOnceAsync(ct);
                }
                else if (_paused)
                {
                    SetState(GuardState.Paused, "已暂停（不自动认证）");
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Log.Error("检测异常：" + ex.Message);
                SetState(GuardState.Error, "检测异常：" + ex.Message);
            }

            int wait = Math.Max(2, _cfg.IntervalSeconds) * 1000;
            try
            {
                await _wake.WaitAsync(wait, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task CheckOnceAsync(CancellationToken ct)
    {
        SetState(GuardState.Checking, "正在检测网络…");

        bool online = await _client.IsInternetOkAsync(ct);
        if (online)
        {
            _failCount = 0;
            OnlineSince ??= DateTime.Now;
            SetState(GuardState.Online, _portal != null ? $"在线 · 门户 {HostOf(_portal)}" : "网络正常");

            if (_cfg.KeepAliveSeconds > 0 && _portal != null &&
                (DateTime.Now - _lastKeepAlive).TotalSeconds >= _cfg.KeepAliveSeconds)
            {
                _lastKeepAlive = DateTime.Now;
                await _client.KeepAliveAsync(_portal, ct);
            }
            return;
        }

        OnlineSince = null;
        _failCount++;
        SetState(GuardState.Offline, $"网络已断开（连续 {_failCount} 次）");

        if (_failCount < Math.Max(1, _cfg.FailThreshold)) return;

        _failCount = 0;

        // 账号密码类错误后冷却一段时间，避免把账号试锁
        if (DateTime.Now < _credentialCooldownUntil)
        {
            int left = (int)Math.Ceiling((_credentialCooldownUntil - DateTime.Now).TotalSeconds);
            SetState(GuardState.Error, $"账号认证失败，{left} 秒后重试（请检查密码）");
            return;
        }

        await LoginFlowAsync(ct);
    }

    private async Task LoginFlowAsync(CancellationToken ct)
    {
        if (_loginInProgress) return;
        _loginInProgress = true;
        try
        {
            SetState(GuardState.LoggingIn, "检测到断网，正在认证…");

            if (string.IsNullOrWhiteSpace(_cfg.Username) || string.IsNullOrWhiteSpace(_cfg.Password))
            {
                SetState(GuardState.Error, "未配置账号密码，请先在设置里填写");
                return;
            }

            if (!string.IsNullOrWhiteSpace(_cfg.PortalUrl))
            {
                _portal = _cfg.PortalUrl.TrimEnd('/');
            }

            if (_portal == null)
            {
                _portal = await _client.DiscoverPortalAsync(ct);
                if (_portal == null)
                {
                    SetState(GuardState.Error, "找不到认证门户，请手动填写门户地址");
                    return;
                }
            }

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                if (ct.IsCancellationRequested) return;

                var result = await _client.LoginAsync(_portal!, _cfg.Username, _cfg.Password, _cfg.AcId, ct);
                if (result.Success)
                {
                    Log.Info("认证成功：" + result.Message);
                    await Task.Delay(1500, ct);
                    if (await _client.IsInternetOkAsync(ct))
                    {
                        OnlineSince = DateTime.Now;
                        _lastKeepAlive = DateTime.Now;
                        _loginCount++;
                        _loginFailStreak = 0;
                        _credentialCooldownUntil = DateTime.MinValue;
                        SetState(GuardState.Online, "认证成功，网络已恢复");
                        LoginSucceeded?.Invoke(result.Message);
                        return;
                    }
                    Log.Warn("认证接口返回成功，但网络仍不通，继续重试…");
                }
                else
                {
                    _lastLoginMessage = result.Message;
                    Log.Warn($"第 {attempt} 次认证失败：{result.Message}");
                    // 门户地址可能变了，清掉重新探测
                    if (attempt >= 2) _portal = null;
                }

                if (attempt < 3) await Task.Delay(3000, ct);
            }

            // 3 次都失败，重新探测门户后留给下一轮
            _portal = string.IsNullOrWhiteSpace(_cfg.PortalUrl) ? null : _cfg.PortalUrl.TrimEnd('/');

            _loginFailStreak++;
            string last = _lastLoginMessage;

            if (IsCredentialError(last))
            {
                _credentialCooldownUntil = DateTime.Now.AddMinutes(2);
                Log.Error("账号或密码被拒绝：" + last + "，暂停 2 分钟再试");
                Notify?.Invoke("账号或密码不正确，已暂停 2 分钟后再试", true);
            }
            else if (_loginFailStreak >= 5)
            {
                Log.Warn($"连续 {_loginFailStreak} 轮认证失败，暂停 1 分钟");
                _credentialCooldownUntil = DateTime.Now.AddMinutes(1);
                Notify?.Invoke("多次认证失败，稍后自动重试", true);
            }

            // 兜底：直接拉起官方客户端，保证这次也能连上
            if (_cfg.FallbackEnabled && !string.IsNullOrWhiteSpace(_cfg.FallbackCommand) &&
                (DateTime.Now - _lastFallback).TotalSeconds > 60)
            {
                _lastFallback = DateTime.Now;
                try
                {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_cfg.FallbackCommand)
                    {
                        UseShellExecute = true
                    });
                    Log.Info("已启动备用客户端：" + _cfg.FallbackCommand);
                }
                catch (Exception ex)
                {
                    Log.Warn("启动备用客户端失败：" + ex.Message);
                }
            }

            SetState(GuardState.Error, "自动认证失败，稍后重试");
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error("认证流程异常：" + ex.Message);
            SetState(GuardState.Error, "认证异常：" + ex.Message);
        }
        finally
        {
            _loginInProgress = false;
        }
    }

    /// <summary>判断失败原因是不是账号密码类（这类重试没意义，还会把账号试锁）。</summary>
    private static bool IsCredentialError(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return false;
        string[] keys = { "密码", "账号", "余额", "锁定", "password", "username", "user_not_found", "insufficient" };
        return keys.Any(k => message.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static string HostOf(string url)
    {
        try { return new Uri(url).Host; } catch { return url; }
    }

    private void SetState(GuardState state, string message)
    {
        State = state;
        try { StateChanged?.Invoke(state, message); } catch { }
    }

    public void Dispose()
    {
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkChanged;
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        Microsoft.Win32.SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        Stop();
        _client.Dispose();
        _wake.Dispose();
    }
}
