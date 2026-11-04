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
