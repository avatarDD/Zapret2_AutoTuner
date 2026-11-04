using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Geneva.Auto;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Tuning.Geneva;

namespace ZapretAutoTuner.App.Tests;

/// <summary>Everything in one folder next to the program, and what an export of the "Авто" mode lets out.</summary>
public sealed class PortableTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "zt-portable-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    [Fact]
    public void The_data_lives_next_to_the_program_and_the_old_folder_moves_into_it()
    {
        var program = Path.Combine(_root, "AutoTuner");
        var legacy = Path.Combine(_root, "LocalAppData", "ZapretAutoTuner");
        Directory.CreateDirectory(Path.Combine(legacy, "exports"));
        File.WriteAllText(Path.Combine(legacy, "knowledge.db"), "kb");
        File.WriteAllText(Path.Combine(legacy, "exports", "a.conf"), "x");
        File.WriteAllText(Path.Combine(legacy, "agent-1.sock"), "");
        Directory.CreateDirectory(program);

        var dir = PortableData.Resolve(program, legacy, privileged: false);

        Assert.Equal(Path.Combine(program, "data"), dir);
        Assert.Equal("kb", File.ReadAllText(Path.Combine(dir, "knowledge.db")));
        Assert.Equal("x", File.ReadAllText(Path.Combine(dir, "exports", "a.conf")));
        // an old session's socket is not carried over, and the old folder is gone once all was copied
        Assert.False(File.Exists(Path.Combine(dir, "agent-1.sock")));
        Assert.False(Directory.Exists(legacy));
        // the next start finds its data where it is
        Assert.Equal(dir, PortableData.Resolve(program, legacy, privileged: false));
    }

    [Fact]
    public void Data_already_next_to_the_program_is_not_overwritten_by_the_old_folder()
    {
        var program = Path.Combine(_root, "p");
        var legacy = Path.Combine(_root, "old");
        Directory.CreateDirectory(Path.Combine(program, "data"));
        Directory.CreateDirectory(legacy);
        File.WriteAllText(Path.Combine(program, "data", "knowledge.db"), "new");
        File.WriteAllText(Path.Combine(legacy, "knowledge.db"), "old");
        Assert.Equal(Path.Combine(program, "data"), PortableData.Resolve(program, legacy, privileged: false));
        Assert.Equal("new", File.ReadAllText(Path.Combine(program, "data", "knowledge.db")));
        Assert.True(File.Exists(Path.Combine(legacy, "knowledge.db")));
    }

    private static void Kb(string dir, Action<ZapretAutoTuner.Storage.KnowledgeBase> fill)
    {
        Directory.CreateDirectory(dir);
        using var kb = ZapretAutoTuner.Storage.KnowledgeBase.Open(Path.Combine(dir, "knowledge.db"));
        fill(kb);
    }

    private static T WithKb<T>(string dir, Func<ZapretAutoTuner.Storage.KnowledgeBase, T> read)
    {
        using var kb = ZapretAutoTuner.Storage.KnowledgeBase.Open(Path.Combine(dir, "knowledge.db"));
        return read(kb);
    }

    private static string State(params (string Host, string Strategy)[] found) => new GenevaState
    {
        Found = [.. found.Select(f => new GenevaFoundStrategy { Host = f.Host, Strategy = f.Strategy, Fitness = 390 })],
    }.Serialize();

    [Fact]
    public void A_knowledge_base_of_the_last_version_is_read_after_the_move()
    {
        var program = Path.Combine(_root, "v2");
        var legacy = Path.Combine(_root, "v1");
        Kb(legacy, kb =>
        {
            kb.SetSetting("geneva.state", State(("youtube.com", "A")));
            kb.SetSetting("language", "en");
        });
        var dir = PortableData.Resolve(program, legacy, privileged: false);
        Assert.Equal("youtube.com", WithKb(dir, kb => GenevaState.Parse(kb.GetSetting("geneva.state")).Found.Single().Host));
        Assert.Equal("en", WithKb(dir, kb => kb.GetSetting("language")));
    }

    [Fact]
    public void A_new_base_with_nothing_in_it_gives_way_to_the_old_one()
    {
        // this version started once before the old data could move (or the old version still held it)
        var program = Path.Combine(_root, "v2");
        var legacy = Path.Combine(_root, "v1");
        Kb(legacy, kb => kb.SetSetting("geneva.state", State(("youtube.com", "A"))));
        Kb(Path.Combine(program, "data"), kb => kb.SetSetting("language", "ru"));
        var dir = PortableData.Resolve(program, legacy, privileged: false);
        Assert.Equal("A", WithKb(dir, kb => GenevaState.Parse(kb.GetSetting("geneva.state")).Found.Single().Strategy));
        Assert.Contains(Directory.EnumerateFiles(dir), f => Path.GetFileName(f).StartsWith("knowledge.db.unused-", StringComparison.Ordinal));
        Assert.False(File.Exists(Path.Combine(legacy, "knowledge.db")));
    }

    [Fact]
    public void A_new_base_in_use_gets_the_old_ones_strategies_merged_in_once()
    {
        var program = Path.Combine(_root, "v2");
        var legacy = Path.Combine(_root, "v1");
        Kb(legacy, kb =>
        {
            kb.SetSetting("geneva.state", State(("youtube.com", "A"), ("discord.com", "B")));
            kb.SetSetting("language", "en");
            kb.SetSetting("only.old", "1");
            kb.AddChange("youtube.com", "test", "old history");
        });
        File.WriteAllText(Path.Combine(legacy, "current-solution.json"), "{}");
        Kb(Path.Combine(program, "data"), kb =>
        {
            kb.SetSetting("geneva.state", State(("x.com", "C"), ("youtube.com", "A")));
            kb.SetSetting("language", "ru");
        });
        var dir = PortableData.Resolve(program, legacy, privileged: false);
        var found = WithKb(dir, kb => GenevaState.Parse(kb.GetSetting("geneva.state")).Found.Select(f => f.Host).Order().ToList());
        Assert.Equal(["discord.com", "x.com", "youtube.com"], found);
        // what the new base has stays; what only the old had comes over
        Assert.Equal("ru", WithKb(dir, kb => kb.GetSetting("language")));
        Assert.Equal("1", WithKb(dir, kb => kb.GetSetting("only.old")));
        Assert.True(File.Exists(Path.Combine(dir, "current-solution.json")));
        // the old base is renamed: the next start merges nothing again
        Assert.False(File.Exists(Path.Combine(legacy, "knowledge.db")));
        Assert.Contains(Directory.EnumerateFiles(legacy), f => Path.GetFileName(f).StartsWith("knowledge.db.merged-", StringComparison.Ordinal));
        Assert.Equal(dir, PortableData.Resolve(program, legacy, privileged: false));
    }

    [Fact]
    public void An_elevated_start_leaves_the_data_where_it_is()
    {
        var program = Path.Combine(_root, "pf");
        var legacy = Path.Combine(_root, "user");
        Directory.CreateDirectory(program);
        Directory.CreateDirectory(legacy);
        File.WriteAllText(Path.Combine(legacy, "knowledge.db"), "kb");
        Assert.Equal(legacy, PortableData.Resolve(program, legacy, privileged: true));
        Assert.True(File.Exists(Path.Combine(legacy, "knowledge.db")));
        Assert.False(Directory.Exists(Path.Combine(program, "data")));
        // data a usual start already moved next to the program stays in use
        Assert.Equal(Path.Combine(program, "data"), PortableData.Resolve(program, legacy, privileged: false));
        Assert.Equal(Path.Combine(program, "data"), PortableData.Resolve(program, legacy, privileged: true));
    }

    [Fact]
    public void A_read_only_program_folder_keeps_the_users_folder()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root")
            return; // root writes anywhere; Windows needs an ACL for this
        var program = Path.Combine(_root, "ro");
        Directory.CreateDirectory(program);
        File.SetUnixFileMode(program, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            var legacy = Path.Combine(_root, "home");
            Assert.Equal(legacy, PortableData.Resolve(program, legacy, privileged: false));
        }
        finally
        {
            File.SetUnixFileMode(program, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    [Fact]
    public void The_export_names_services_by_domain_or_protocol_never_by_address()
    {
        var t0 = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        AutoService S(string key, AutoKind kind, string name, string host, string app, string strategy) => new()
        {
            Key = key, Kind = kind, Transport = kind is AutoKind.Web ? L4Kind.Tcp : L4Kind.Udp, Name = name, Host = host, App = app,
            Status = AutoStatus.Applied, Strategy = strategy, Fitness = 390, Addresses = [new AutoAddress("203.0.113.9", t0)],
        };
        var services = new[]
        {
            S("web:youtube.com", AutoKind.Web, "youtube.com", "www.youtube.com", "tls", "T"),
            S("quic:ytimg.com", AutoKind.Quic, "ytimg.com (QUIC)", "i.ytimg.com", "quic", "U"),
            S("dns:203.0.113.9", AutoKind.Dns, "DNS 203.0.113.9", "", "dns", "D"),
            S("ep:wireguard:udp:203.0.113.9:51820", AutoKind.Endpoint, "WireGuard 203.0.113.9:51820", "", "wireguard", "W"),
            S("ep:tls:tcp:203.0.113.9:443", AutoKind.Endpoint, "TCP 203.0.113.9:443", "203.0.113.9", "tcp", "X"),
        };
        var state = new GenevaState { Found = [new GenevaFoundStrategy { Host = "8.8.8.8", Strategy = "R", Fitness = 300 }, new GenevaFoundStrategy { Host = "rutor.info", Strategy = "F", Fitness = 380 }] };
        var items = AutoViewModel.ExportItems(state, services);
        var names = items.SelectMany(i => i.Services).ToList();
        Assert.Equal(["youtube.com", "ytimg.com", "DNS", "wireguard", "tcp", "rutor.info"], names);
        Assert.DoesNotContain(names, n => n.Contains("203.0.113", StringComparison.Ordinal) || n.Contains("8.8.8.8", StringComparison.Ordinal));
        Assert.Equal(7, items.Count);
    }
}
