using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.App.Views;
using ZapretAutoTuner.Core.Model;
using ZapretAutoTuner.Core.Resources;
using ZapretAutoTuner.Delivery;
using ZapretAutoTuner.Storage;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.App.Tests;

/// <summary>The Resources page (PLAN 4a.5): editing, deleting a used resource, Lua approval only in the window, the router after a yes.</summary>
public sealed class ResourcesTests : IAsyncLifetime
{
    private const string Lua = "function zt_twice(ctx, desync) return VERDICT_PASS end\n";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-res-" + Guid.NewGuid().ToString("N"));
    private AppHost? _host;

    private AppHost Host => _host!;

    public Task InitializeAsync()
    {
        SessionState.I.Last = null;
        _host = new AppHost(_dir);
        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        SessionState.I.Last = null;
        if (_host is not null)
            await _host.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_dir, recursive: true);
    }

    private sealed class FakeRouter : IRouterResourceProvider
    {
        public int Ran { get; private set; }

        public Exception? Fails { get; set; }

        public string? Describe() => "zapret-gui http://192.168.1.1:8080/";

        public Task<RouterResourceOperation> PrepareAsync(RouterResourceAction action, ResourceKind kind, string name, CancellationToken ct)
        {
            if (Fails is not null)
                throw Fails;
            return Task.FromResult(new RouterResourceOperation(RouterResources.ZapretGui, action, new ResourceRef(kind, name),
                [new DeliveryStep($"записать {name}", $"write {name}")], "превью", "preview", _ =>
                {
                    Ran++;
                    return Task.FromResult(new DeliveryResult(true, false, [], null));
                }));
        }
    }

    private static Solution Using(string hostlist)
    {
        var s = new Solution();
        s.Profiles.Add(new Profile { Name = "p", TcpPorts = "443", Hostlists = [new ListRef(hostlist)], Strategy = Strategy.Parse("--lua-desync=multisplit:pos=1") });
        return s;
    }

    [AvaloniaFact]
    public async Task AHostlistIsCreatedAndAUsedOneIsNotDeleted()
    {
        var vm = new ResourcesViewModel(Host.Resources);
        int asked = 0;
        vm.Confirm = (_, _) =>
        {
            asked++;
            return Task.FromResult(true);
        };
        vm.Name = "video";
        vm.Content = "Example.COM\nhttps://www.example.org/watch\n*.cdn.example.net";
        vm.SaveCommand.Execute(null);
        Assert.Equal("video", Assert.Single(vm.Items).Name);
        Assert.Equal("video", vm.Selected?.Name);
        Assert.False(vm.IsNew);
        Assert.Contains(vm.Problems, p => p.StartsWith('⚠'));   // "*." dropped with a warning
        Assert.Equal(["example.com", "www.example.org", "cdn.example.net"], Host.Resources.Get(ResourceKind.Hostlist, "video")!.Data.Items);

        // the current solution uses it: the session keeps the references, the delete names the user and asks nothing
        SessionState.I.Last = new PipelineResult([], null, Using("video"));
        vm.Reload();
        await vm.DeleteCommand.ExecuteAsync(null);
        Assert.Equal(0, asked);
        Assert.Contains(Loc.Loc.I.English ? "current solution" : "текущее решение", vm.Status, StringComparison.Ordinal);
        Assert.Single(Host.Resources.List());

        SessionState.I.Last = null;
        vm.Reload();
        await vm.DeleteCommand.ExecuteAsync(null);
        Assert.Equal(1, asked);
        Assert.Empty(Host.Resources.List());
        Assert.Empty(vm.Items);
    }

    [AvaloniaFact]
    public void BadContentShowsTheErrors()
    {
        var vm = new ResourcesViewModel(Host.Resources) { KindIndex = 2 };
        Assert.True(vm.IsBlob);
        vm.Name = "bad-blob";
        vm.Content = "0102";
        vm.SaveCommand.Execute(null);
        Assert.Empty(Host.Resources.List());
        Assert.Contains(vm.Problems, p => p.StartsWith('✖'));
        vm.Name = "tls_wl";
        vm.SaveCommand.Execute(null);
        Assert.Equal([1, 2], Host.Resources.Get(ResourceKind.Blob, "tls_wl")!.Data.Bytes);
    }

    [AvaloniaFact]
    public async Task ALuaScriptIsApprovedOnlyThroughTheDialogWithTheVersionShown()
    {
        var vm = new ResourcesViewModel(Host.Resources) { KindIndex = 3 };
        LuaApprovalRequest? shown = null;
        bool answer = false;
        vm.ApproveDialog = r =>
        {
            shown = r;
            return Task.FromResult(answer);
        };
        vm.Name = "twice";
        vm.Content = Lua;
        vm.SaveCommand.Execute(null);
        Assert.Equal(LuaApproval.Draft, Host.Resources.List(ResourceKind.LuaScript)[0].Approval);

        await vm.ApproveCommand.ExecuteAsync(null);
        Assert.NotNull(shown);
        Assert.Equal(Lua, shown!.Source);
        Assert.Equal(1, shown.Version);
        Assert.Null(shown.ApprovedVersion);
        Assert.Equal(1, shown.Diff.Added);
        Assert.Equal(LuaApproval.Draft, Host.Resources.List(ResourceKind.LuaScript)[0].Approval);   // "Отмена"

        answer = true;
        await vm.ApproveCommand.ExecuteAsync(null);
        Assert.Equal(LuaApproval.Approved, Host.Resources.List(ResourceKind.LuaScript)[0].Approval);

        // an edit is a new draft; the dialog shows the diff from the approved version
        vm.Content = Lua + "-- v2\n";
        vm.SaveCommand.Execute(null);
        Assert.Equal(LuaApproval.ApprovedWithNewDraft, Host.Resources.List(ResourceKind.LuaScript)[0].Approval);
        vm.Content = Lua + "-- v3 not saved\n";
        await vm.ApproveCommand.ExecuteAsync(null);
        Assert.Equal(1, shown.Version);   // nothing shown: unsaved text is never approved
        vm.Content = Lua + "-- v2\n";
        await vm.ApproveCommand.ExecuteAsync(null);
        Assert.Equal(2, shown.Version);
        Assert.Equal(1, shown.ApprovedVersion);
        Assert.Contains(shown.Diff.Lines, l => l.Kind == DiffKind.Added && l.Text == "-- v2");
        Assert.Equal(2, Host.Resources.List(ResourceKind.LuaScript)[0].ApprovedVersion);
    }

    [AvaloniaFact]
    public async Task TheRouterChangesOnlyAfterTheUserSawThePlan()
    {
        Host.Resources.Create(ResourceInput.Hostlist("video", ["example.com"]));
        var router = new FakeRouter();
        var vm = new ResourcesViewModel(Host.Resources, router);
        string? text = null;
        bool yes = false;
        vm.Confirm = (_, t) =>
        {
            text = t;
            return Task.FromResult(yes);
        };
        vm.Selected = vm.Items[0];
        await vm.PushCommand.ExecuteAsync(null);
        Assert.Contains("video", text, StringComparison.Ordinal);
        Assert.Equal(0, router.Ran);
        yes = true;
        await vm.RouterDeleteCommand.ExecuteAsync(null);
        Assert.Equal(1, router.Ran);
        Assert.False(vm.HasProblem);

        BugReportInput? reported = null;
        vm.ReportProblem = i =>
        {
            reported = i;
            return Task.CompletedTask;
        };
        router.Fails = new ZapretGuiException("POST /api/hostlists/create: 500 boom");
        await vm.PushCommand.ExecuteAsync(null);
        Assert.True(vm.HasProblem);
        await vm.ReportProblemCommand.ExecuteAsync(null);
        Assert.Equal(BugKind.ZapretGuiError, reported?.Kind);
        Assert.Equal(BugTarget.ZapretGui, BugReport.SuggestTarget(reported!).Target);
    }

    [AvaloniaFact]
    public void ApprovedUserLuaWorksInTheExpertAndTheExport()
    {
        Host.Resources.Create(ResourceInput.Lua("twice", Lua));
        var e = new ExpertViewModel { Resources = Host.Resources, ImportText = "--filter-tcp=443 --hostlist-domains=example.com --lua-desync=zt_twice" };
        e.ImportCommand.Execute(null);
        Assert.False(e.CanUse);   // a draft is refused
        Host.Resources.Approve("twice", 1, confirmedByUser: true);
        e.ImportCommand.Execute(null);
        Assert.True(e.CanUse, string.Join("\n", e.Issues));
        e.UseCommand.Execute(null);
        // the current solution now refers to the script: it cannot be deleted
        Assert.Throws<ResourceException>(() => Host.Resources.Delete(ResourceKind.LuaScript, "twice"));

        var w = new WizardViewModel(Host) { CopyText = _ => Task.CompletedTask };
        w.ExportCommand.Execute("argv");
        Assert.True(SessionState.I.Last!.Solution!.LuaFiles.ContainsKey("zt-twice.lua"), w.ExportStatus);
    }

    [AvaloniaFact]
    public void TheResourcesPageAndDialogsRender()
    {
        Host.Resources.Create(ResourceInput.Lua("twice", Lua));
        Host.Resources.Create(ResourceInput.Hostlist("video", ["example.com"]));
        // the page alone: a MainViewModel would leave its language subscriptions behind for the other tests
        var vm = new ResourcesViewModel(Host.Resources, new FakeRouter());
        var window = new Window { Content = new ResourcesView { DataContext = vm } };
        window.Show();
        for (int k = 0; k < 4; k++)
        {
            vm.KindIndex = k;
            if (vm.Items.Count > 0)
                vm.Selected = vm.Items[0];
            window.UpdateLayout();
        }
        Assert.Contains("zapret-gui", vm.RouterText, StringComparison.Ordinal);
        var request = new LuaApprovalRequest("twice", 1, null, Lua, Host.Resources.Diff("twice"), [new ResourceProblem(false, "lua.risky", "предупреждение", "warning")]);
        var dialog = new Window { Content = LuaApprovalDialog.Build(request, out var yes, out var no) };
        dialog.Show();
        dialog.UpdateLayout();
        Assert.True(no.IsDefault);
        Assert.False(yes.IsDefault);
        dialog.Close();

        var report = new Window { Content = new BugReportView { DataContext = new BugReportViewModel(BugReports.From(new InvalidOperationException("boom"))) } };
        report.Show();
        report.UpdateLayout();
        report.Close();
        window.Close();
    }

    [AvaloniaFact]
    public void A_name_with_an_extension_is_saved_and_an_imported_strategy_finds_the_list()
    {
        var vm = new ResourcesViewModel(Host.Resources) { Name = "video.txt", Content = "example.com" };
        vm.SaveCommand.Execute(null);
        Assert.NotNull(Host.Resources.Get(ResourceKind.Hostlist, "video"));

        var e = new ExpertViewModel { Resources = Host.Resources, ImportText = @"--filter-tcp=443 --hostlist=C:\zapret\lists\video.txt --lua-desync=multisplit:pos=1" };
        e.ImportCommand.Execute(null);
        Assert.True(e.CanUse, string.Join("\n", e.Issues));
        Assert.True(e.Issues.Any(i => i.StartsWith("✓", StringComparison.Ordinal) && i.Contains("video", StringComparison.Ordinal)), string.Join("\n", e.Issues) + " / " + string.Join(";", e.Profiles));
        Assert.DoesNotContain(e.Issues, i => i.StartsWith("⚠", StringComparison.Ordinal));
    }
}

/// <summary>"Сообщить о проблеме" (PLAN 4a.6): the draft, the tracker choice, and nothing opened or sent without a button.</summary>
public sealed class BugReportDialogTests
{
    [AvaloniaFact]
    public async Task TheDraftIsEditedCopiedAndOpenedOnlyOnClick()
    {
        var copied = new List<string>();
        var opened = new List<Uri>();
        var vm = new BugReportViewModel(new BugReportInput { Kind = BugKind.EngineRefused, Summary = "winws2 refused", EventLog = ["trial 192.168.1.10"], Russian = false })
        {
            CopyText = t =>
            {
                copied.Add(t);
                return Task.CompletedTask;
            },
            OpenUrl = u =>
            {
                opened.Add(u);
                return Task.CompletedTask;
            },
            SaveArchive = () => Task.FromResult<string?>("autotuner-report-1.zip"),
        };
        Assert.Empty(opened);
        Assert.Equal((int)BugTarget.AutoTuner, vm.TargetIndex);
        Assert.DoesNotContain("192.168.1.10", vm.Text, StringComparison.Ordinal);

        vm.TargetIndex = (int)BugTarget.Zapret2;
        Assert.Equal("bol-van/zapret2", vm.Draft.Target.Repository);

        await vm.SaveArchiveCommand.ExecuteAsync(null);
        Assert.Contains("autotuner-report-1.zip", vm.Text, StringComparison.Ordinal);

        await vm.CopyCommand.ExecuteAsync(null);
        Assert.Contains(vm.Title, copied.Single(), StringComparison.Ordinal);

        vm.Text += "\nmy own words";
        await vm.OpenGitHubCommand.ExecuteAsync(null);
        var url = Assert.Single(opened).ToString();
        Assert.StartsWith("https://github.com/bol-van/zapret2/issues/new", url, StringComparison.Ordinal);
        Assert.Contains("my own words", Uri.UnescapeDataString(url), StringComparison.Ordinal);

        // too long for a link: the full text goes to the clipboard and the page gets a paste note
        vm.Text = new string('x', 20_000);
        var (_, paste) = vm.IssueUrl();
        Assert.True(paste);
        await vm.OpenGitHubCommand.ExecuteAsync(null);
        Assert.Equal(vm.Text, copied.Last());
        Assert.True(opened.Last().ToString().Length < BugReport.MaxUrlLength);
    }

    [AvaloniaFact]
    public void TheReportsPageOpensTheDialogWithTheRunsData()
    {
        var reports = new ReportsViewModel { MaskDomains = true, Environment = "VirtualBox" };
        BugReportInput? got = null;
        reports.ReportProblem = i =>
        {
            got = i;
            return Task.CompletedTask;
        };
        reports.ReportProblemCommand.Execute(null);
        Assert.NotNull(got);
        Assert.True(got!.MaskDomains);
        Assert.Equal(["VirtualBox"], got.Environment);
    }
}
