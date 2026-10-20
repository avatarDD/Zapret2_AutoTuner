using System.Net;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Packets;
using ZapretAutoTuner.Core.Programs;
using ZapretAutoTuner.Probes.Programs;
using static ZapretAutoTuner.Tuning.Tests.ProgramFixtures;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>Recording a program (PLAN 6.2): capture in the Agent, sockets per process, flows on them as endpoints.</summary>
public sealed class ProgramRecorderTests
{
    private const string Me = "192.168.1.2";

    /// <summary>The program's STUN gets no answer; its WireGuard works; another program talks on another port.</summary>
    private static List<CapturedPacket> Packets() => Capture(
        Udp(Me, 50000, "198.51.100.7", 3478, Stun()),
        Udp(Me, 50000, "198.51.100.7", 3478, Stun()),
        Udp(Me, 50000, "198.51.100.7", 3478, Stun()),
        Udp(Me, 50000, "198.51.100.7", 3478, Stun()),
        Udp(Me, 50001, "203.0.113.9", 51820, new byte[148].Select((b, i) => i == 0 ? (byte)1 : b).ToArray()),
        Udp("203.0.113.9", 51820, Me, 50001, new byte[92]),
        Udp("203.0.113.9", 51820, Me, 50001, new byte[200]),
        Udp(Me, 60000, "203.0.113.50", 3478, Stun()));

    private static FakeMonitor Monitor() => new(Packets(), new Dictionary<int, ObservedSocket[]>
    {
        [100] = [new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50000), null)],
        [200] = [new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50001), null), new ObservedSocket(L4Kind.Udp, new IPEndPoint(IPAddress.Any, 50000), null)],
    })
    { Dropped = 7 };

    private static RecordOptions Options(params int[] pids) => new()
    {
        Duration = TimeSpan.FromMilliseconds(250),
        PollInterval = TimeSpan.FromMilliseconds(40),
        Pids = () => pids.ToHashSet(),
    };

    [Fact]
    public async Task Sockets_of_the_program_select_its_flows()
    {
        var monitor = Monitor();
        var progress = new List<double>();
        var rec = await ProgramRecorder.RecordAsync(monitor, Options(100, 200, 300), new SyncProgress(progress.Add));

        Assert.Equal(1, monitor.Starts);
        Assert.Equal([("cap1", false)], monitor.Stops); // stopped without a cancellable token
        Assert.Contains(300, monitor.Listed); // a process that exited is skipped, not fatal
        Assert.Equal(new HashSet<int> { 100, 200, 300 }, rec.Pids.ToHashSet());
        Assert.Equal(2, rec.Sockets); // the same socket seen twice counts once
        Assert.Equal(8, rec.Packets);
        Assert.Equal(7, rec.Dropped);

        Assert.Equal(2, rec.Endpoints.Count);
        var wg = rec.Endpoints[0];
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 51820), wg.Remote);
        Assert.Equal(AppProtocol.WireGuard, wg.App);
        Assert.Equal(FlowHealth.Ok, wg.Health);
        var stun = rec.Endpoints[1];
        Assert.Equal(AppProtocol.Stun, stun.App);
        Assert.Equal(FlowHealth.NoReply, stun.Health);
        Assert.Equal(4, stun.InitialPayloads.Count);
        Assert.Equal([stun], rec.Broken);

        Assert.NotEmpty(progress);
        Assert.All(progress, p => Assert.InRange(p, 0, 1));
    }

    [Fact]
    public async Task Capture_is_stopped_when_the_recording_is_cancelled()
    {
        var monitor = Monitor();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var options = Options(100) with { Duration = TimeSpan.FromSeconds(30) };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProgramRecorder.RecordAsync(monitor, options, ct: cts.Token));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10));
        Assert.Equal([("cap1", false)], monitor.Stops);
    }

    [Fact]
    public async Task Capture_is_stopped_when_listing_throws()
    {
        var monitor = Monitor();
        var options = Options(100) with { Pids = () => throw new InvalidOperationException("boom") };
        await Assert.ThrowsAsync<InvalidOperationException>(() => ProgramRecorder.RecordAsync(monitor, options));
        Assert.Single(monitor.Stops);
    }

    [Fact]
    public async Task Recording_needs_the_program_processes()
    {
        var monitor = Monitor();
        await Assert.ThrowsAsync<ArgumentException>(() => ProgramRecorder.RecordAsync(monitor, new RecordOptions()));
        Assert.Equal(0, monitor.Starts);
    }

    [Fact]
    public void Folders_on_path_are_shared()
    {
        var first = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (first is not null)
        {
            Assert.True(ProgramRecorder.IsSharedDirectory(first));
            Assert.True(ProgramRecorder.IsSharedDirectory(first.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar));
        }
        var own = Directory.CreateTempSubdirectory("ztuner-prog-").FullName;
        try
        {
            Assert.False(ProgramRecorder.IsSharedDirectory(own));
        }
        finally
        {
            Directory.Delete(own);
        }
        if (OperatingSystem.IsWindows())
            Assert.True(ProgramRecorder.IsSharedDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32")));
    }

    [Fact]
    public void Launch_needs_an_executable()
    {
        Assert.Throws<InvalidOperationException>(() => ProgramRecorder.Launch(new ProgramInfo { Id = "x", Name = "X", Source = ProgramSource.Uninstall }));
    }

    [Fact]
    public void Default_pids_keep_the_root_while_it_lives()
    {
        var self = Environment.ProcessId;
        var pids = ProgramRecorder.DefaultPids(new ProgramInfo { Id = "u", Name = "U", Source = ProgramSource.Uwp, Executable = "explorer.exe" }, self)();
        Assert.Contains(self, pids);
    }

    [Fact]
    public void A_packaged_app_is_found_by_its_install_folder()
    {
        var dir = OperatingSystem.IsWindows() ? @"C:\Program Files\WindowsApps\Vendor.App_1.0_x64" : "/opt/windowsapps/vendor.app";
        var app = new ProgramInfo { Id = "Vendor.App!App", Name = "App", Source = ProgramSource.Uwp, Executable = "explorer.exe", Arguments = [@"shell:AppsFolder\Vendor.App!App"], InstallDirectory = dir };
        Assert.Equal(dir, ProgramRecorder.OwnDirectory(app));
        var snaps = new Queue<Dictionary<int, ProcessEntry>>();
        Dictionary<int, ProcessEntry> Snap(params (int Pid, int Parent, long Start)[] l) => l.ToDictionary(x => x.Pid, x => new ProcessEntry(x.Pid, x.Parent, x.Start));
        // explorer (5) starts the shell launch and exits; the app (40) is started by the broker (8), not by us
        snaps.Enqueue(Snap((5, 1, 10), (8, 1, 5)));
        snaps.Enqueue(Snap((8, 1, 5), (40, 8, 20), (41, 40, 21), (50, 8, 22)));
        snaps.Enqueue(Snap((8, 1, 5), (41, 40, 21), (50, 8, 22)));
        var images = new ProcessImageCache(pid => pid is 40 or 41 ? Path.Combine(dir, "app.exe") : "/usr/bin/other");
        var pids = ProgramRecorder.DefaultPids(app, 5, () => snaps.Dequeue(), images);
        Assert.Equal(new HashSet<int> { 40, 41 }, pids());
        Assert.Equal(new HashSet<int> { 41 }, pids()); // 40 exited
        // without the install folder nothing of the app would be seen
        Assert.Null(ProgramRecorder.OwnDirectory(app with { InstallDirectory = null }));
    }

    [Fact]
    public void Default_pids_do_not_pick_up_a_reused_pid()
    {
        var snaps = new Queue<Dictionary<int, ProcessEntry>>();
        Dictionary<int, ProcessEntry> Snap(params (int Pid, int Parent, long Start)[] l) => l.ToDictionary(x => x.Pid, x => new ProcessEntry(x.Pid, x.Parent, x.Start));
        snaps.Enqueue(Snap((7, 1, 100)));
        snaps.Enqueue(Snap((7, 1, 100), (9, 7, 101)));
        snaps.Enqueue(Snap((9, 7, 101)));
        snaps.Enqueue(Snap((7, 1, 900), (9, 7, 101), (12, 7, 901))); // pid 7 reused by another program
        var program = new ProgramInfo { Id = "p", Name = "P", Source = ProgramSource.Path, Executable = "/usr/bin/p" };
        var pids = ProgramRecorder.DefaultPids(program, 7, () => snaps.Dequeue(), new ProcessImageCache(_ => null));
        Assert.Equal(new HashSet<int> { 7, 9 }, pids());
        Assert.Equal(new HashSet<int> { 9 }, pids());
        Assert.Equal(new HashSet<int> { 9 }, pids());
    }

    /// <summary>IProgress without a synchronization context hop.</summary>
    private sealed class SyncProgress(Action<double> report) : IProgress<double>
    {
        public void Report(double value) => report(value);
    }
}
