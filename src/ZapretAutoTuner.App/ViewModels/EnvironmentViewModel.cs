using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.Probes.Browser;
using ZapretAutoTuner.Tools;

namespace ZapretAutoTuner.App.ViewModels;

/// <summary>How a part of the environment is: fine, worth knowing, limits something, or stops something from working.</summary>
public enum EnvLevel
{
    Ok,
    Info,
    Warning,
    Error,
}

/// <summary>One line of "Состояние": what is checked, what was found, and the one thing to do about it.</summary>
public sealed class EnvRow(string id, string title, EnvLevel level, string text, string? action = null)
{
    public string Id { get; } = id;

    public string Title { get; } = title;

    public EnvLevel Level { get; } = level;

    public string Text { get; } = text;

    /// <summary>The button's text (null: no button); the page knows what it does by <see cref="Id"/>.</summary>
    public string? Action { get; } = action;

    public bool HasAction => Action is not null;

    /// <summary>The mark doubles the colour, so the state is clear without it (and to a screen reader).</summary>
    public string Mark => Level switch
    {
        EnvLevel.Ok => "✓",
        EnvLevel.Info => "i",
        EnvLevel.Warning => "!",
        _ => "✖",
    };

    public string LevelText => Loc.Loc.I["env.level_" + Level.ToString().ToLowerInvariant()];

    public string Brush => Level switch
    {
        EnvLevel.Ok => "#2E9E5B",
        EnvLevel.Info => "#3B82C4",
        EnvLevel.Warning => "#D9A21B",
        _ => "#D0443E",
    };
}

/// <summary>
/// "Состояние": the tools the program needs and whether they are there, checked without rights — the zapret2 and geneva
/// bundles (hashes of the official release), the program's own browser for the final check, the Agent, nft on Linux,
/// the router settings and the data folder. Problems are found at start, not after "Начать" (UX audit P0).
/// </summary>
public sealed partial class EnvironmentViewModel : PageViewModel
{
    private readonly AppHost _host;
    private readonly Func<string?> _agentLost;
    private bool _checking;

    public EnvironmentViewModel(AppHost host, Func<string?> agentLost)
    {
        _host = host;
        _agentLost = agentLost;
        Loc.Loc.I.PropertyChanged += (_, _) => _ = CheckAsync();
    }

    public override string TitleKey => "nav.environment";

    public ObservableCollection<EnvRow> Rows { get; } = [];

    /// <summary>Opens a folder in the file manager; set by the window.</summary>
    public Func<string, Task>? OpenFolder { get; set; }

    /// <summary>Opens a web page (the program's releases); set by the window.</summary>
    public Func<Uri, Task>? OpenUrl { get; set; }

    /// <summary>Where a full build of the program with both engines is published.</summary>
    public static readonly Uri Releases = new("https://github.com/avatarDD/Zapret2_AutoTuner/releases");

    /// <summary>Goes to a page of the window ("settings_router"…); set by the window's view model.</summary>
    public Action<string>? Navigate { get; set; }

    /// <summary>The worst problem found, for the status bar: null when nothing stops the program from working.</summary>
    [ObservableProperty]
    private string? _problem;

    [ObservableProperty]
    private string _summary = "";

    [ObservableProperty]
    private string _checkedAt = "";

    public override void OnShown() => _ = CheckAsync();

    [RelayCommand]
    private Task RecheckAsync() => CheckAsync();

    /// <summary>Checks everything again; cheap enough to run at every visit (a few hashes and two short processes).</summary>
    public async Task CheckAsync()
    {
        if (_checking)
            return;
        _checking = true;
        try
        {
            var rows = new List<EnvRow>
            {
                await Task.Run(Zapret2),
                await GenevaAsync(),
                Browser(),
                Agent(),
            };
            if (OperatingSystem.IsLinux())
                rows.Add(Linux());
            rows.Add(Router());
            rows.Add(new EnvRow("data", L["env.data"], EnvLevel.Info, L.F("env.data_text", _host.DataDir), L["env.open_folder"]));
            Rows.Clear();
            foreach (var r in rows)
                Rows.Add(r);
            var errors = rows.Count(r => r.Level == EnvLevel.Error);
            var warnings = rows.Count(r => r.Level == EnvLevel.Warning);
            Problem = rows.FirstOrDefault(r => r.Level == EnvLevel.Error)?.Title;
            Summary = errors > 0 ? L.F("env.summary_errors", errors) : warnings > 0 ? L.F("env.summary_warnings", warnings) : L["env.summary_ok"];
            CheckedAt = L.F("env.checked_at", DateTime.Now.ToString("HH:mm:ss"));
        }
        finally
        {
            _checking = false;
        }
    }

    private EnvRow Zapret2()
    {
        var b = _host.Bundle;
        if (!File.Exists(b.EnginePath))
            return new("zapret2", "zapret2", EnvLevel.Error, L.F("env.zapret2_missing", b.Root), L["env.how_get"]);
        try
        {
            var check = b.Verify();
            var version = b.ReadManifest()?.Version is { Length: > 0 } v ? v : Core.AppInfo.Zapret2Version;
            return check.Ok
                ? new("zapret2", "zapret2", EnvLevel.Ok, L.F("env.zapret2_ok", version, b.EngineFileName))
                : new("zapret2", "zapret2", EnvLevel.Error, L.F("env.bundle_bad", string.Join("; ", check.Problems)), L["env.how_get"]);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            return new("zapret2", "zapret2", EnvLevel.Error, L.F("env.bundle_bad", e.Message), L["env.how_get"]);
        }
    }

    private async Task<EnvRow> GenevaAsync()
    {
        var b = _host.GenevaBundle;
        if (!b.Exists)
            return new("geneva", "geneva", EnvLevel.Warning, L.F("env.geneva_missing", b.Root), L["env.how_get"]);
        try
        {
            var check = await Task.Run(b.Verify);
            if (!check.Ok)
                return new("geneva", "geneva", EnvLevel.Warning, L.F("env.bundle_bad", string.Join("; ", check.Problems)), L["env.how_get"]);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var v = await b.GetVersionAsync(cts.Token);
            return v.Proto == Core.Geneva.GenevaEvent.Proto
                ? new("geneva", "geneva", EnvLevel.Ok, L.F("env.geneva_ok", v.Version, v.Arch, v.Proto))
                : new("geneva", "geneva", EnvLevel.Warning, L.F("env.geneva_proto", v.Version, v.Proto, Core.Geneva.GenevaEvent.Proto), L["env.how_get"]);
        }
        catch (Exception e) when (e is InvalidOperationException or IOException or FormatException or OperationCanceledException
            or System.ComponentModel.Win32Exception or System.Text.Json.JsonException)
        {
            return new("geneva", "geneva", EnvLevel.Warning, L.F("env.bundle_bad", e.Message), L["env.how_get"]);
        }
    }

    /// <summary>The program's own browser only (project rule: the user's browsers, profiles and settings are never touched).</summary>
    private EnvRow Browser()
    {
        string? path;
        try
        {
            path = BrowserLocator.Chromium();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            path = null;
        }
        return path is not null
            ? new("browser", L["env.browser"], EnvLevel.Ok, L.F("env.browser_ok", path))
            : new("browser", L["env.browser"], EnvLevel.Info, L["env.browser_missing"]);
    }

    private EnvRow Agent()
    {
        if (_agentLost() is { Length: > 0 } lost)
            return new("agent", L["env.agent"], EnvLevel.Warning, L.F("env.agent_lost", lost));
        return _host.AgentRunning
            ? new("agent", L["env.agent"], EnvLevel.Ok, L["env.agent_ok"])
            : new("agent", L["env.agent"], EnvLevel.Info, OperatingSystem.IsWindows() ? L["env.agent_idle_win"] : L["env.agent_idle_linux"]);
    }

    /// <summary>What the Agent needs on Linux: nft for the queue rules, pkexec for the one prompt.</summary>
    private EnvRow Linux()
    {
        var nft = Which("nft");
        var pkexec = Which("pkexec");
        if (nft is null)
            return new("linux", L["env.linux"], EnvLevel.Error, L["env.nft_missing"]);
        return pkexec is null
            ? new("linux", L["env.linux"], EnvLevel.Warning, L.F("env.pkexec_missing", nft))
            : new("linux", L["env.linux"], EnvLevel.Ok, L.F("env.linux_ok", nft, pkexec));
    }

    private EnvRow Router()
    {
        var gui = _host.Settings.GuiUrl;
        var ssh = _host.Settings.RouterHost;
        if (gui.Length == 0 && ssh.Length == 0)
            return new("router", L["env.router"], EnvLevel.Info, L["env.router_none"], L["env.router_setup"]);
        var parts = new List<string>();
        if (gui.Length > 0)
            parts.Add("zapret-gui " + gui);
        if (ssh.Length > 0)
            parts.Add("SSH " + ssh);
        return new("router", L["env.router"], EnvLevel.Ok, L.F("env.router_set", string.Join(", ", parts)), L["env.router_setup"]);
    }

    /// <summary>A program on PATH or in the usual system folders (pkexec runs the Agent as root, where sbin is on PATH).</summary>
    internal static string? Which(string name)
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)
            .Concat(["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"]);
        return dirs.Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);
    }

    [RelayCommand]
    private async Task ActAsync(EnvRow? row)
    {
        switch (row?.Id)
        {
            case "data":
                if (OpenFolder is not null)
                    await OpenFolder(_host.DataDir);
                break;
            case "router":
                Navigate?.Invoke("settings_router");
                break;
            case "zapret2" or "geneva":
                if (OpenUrl is not null)
                    await OpenUrl(Releases);
                break;
        }
    }
}
