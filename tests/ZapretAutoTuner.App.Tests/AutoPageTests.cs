using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.LogicalTree;
using Avalonia.VisualTree;
using ZapretAutoTuner.App.Services;
using ZapretAutoTuner.App.ViewModels;
using ZapretAutoTuner.Core.Geneva.Auto;

namespace ZapretAutoTuner.App.Tests;

/// <summary>The "Авто" page's list of problems: rows stay put while the search moves on, and the "⋯" menu works.</summary>
public sealed class AutoPageTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "zt-auto-" + Guid.NewGuid().ToString("N"));
    private AppHost? _host;

    public Task InitializeAsync()
    {
        _host = new AppHost(_dir);
        return Task.CompletedTask;
    }

    /// <summary>The host stays open, as in <see cref="ViewsTests"/>.</summary>
    public Task DisposeAsync() => Task.CompletedTask;

    private static AutoRowData Row(string key, string status = "блокировка", string detail = "") =>
        new(key, key, status, detail, "", "#D0443E", true, "", false, false, "закрепить");

    [AvaloniaFact]
    public void Rows_keep_their_objects_and_places_and_only_a_resort_moves_them()
    {
        var page = new MainViewModel(_host!).Auto;
        page.SyncRows([Row("a"), Row("b"), Row("c")], resort: true);
        var b = page.AutoServices[1];
        // the search moved on: "c" is searched now and the book would list it first
        page.SyncRows([Row("c", "подбор", "пробую X"), Row("a"), Row("b"), Row("d")], resort: false);
        Assert.Equal(["a", "b", "c", "d"], page.AutoServices.Select(r => r.Key));
        Assert.Same(b, page.AutoServices[1]);
        Assert.Equal("пробую X", page.AutoServices[2].Detail);
        // one leaves, the others stay where they were
        page.SyncRows([Row("c"), Row("b"), Row("d")], resort: false);
        Assert.Equal(["b", "c", "d"], page.AutoServices.Select(r => r.Key));
        Assert.Same(b, page.AutoServices[0]);
        // opening the page or a new filter puts them in the book's order
        page.SyncRows([Row("d"), Row("c"), Row("b")], resort: true);
        Assert.Equal(["d", "c", "b"], page.AutoServices.Select(r => r.Key));
        Assert.Same(b, page.AutoServices[2]);
    }

    [AvaloniaFact]
    public void The_actions_menu_is_enabled_and_reaches_the_page()
    {
        var main = new MainViewModel(_host!);
        var window = new MainWindow { DataContext = main };
        window.Show();
        main.Current = main.Auto;
        main.Auto.SyncRows([Row("web:example.com")], resort: true);
        window.UpdateLayout();
        var button = window.GetVisualDescendants().OfType<Button>().First(b => b.Content as string == "⋯");
        var flyout = Assert.IsType<MenuFlyout>(button.Flyout);
        flyout.ShowAt(button);
        window.UpdateLayout();
        var items = flyout.Items.OfType<MenuItem>().ToList();
        Assert.NotEmpty(items);
        Assert.All(items.Where(i => i.IsVisible), i =>
        {
            Assert.NotNull(i.Command);
            Assert.True(i.IsEffectivelyEnabled, $"«{i.Header}» is disabled");
        });
        flyout.Hide();
        window.Close();
    }

    [Fact]
    public void Do_not_search_takes_the_site_the_name_or_the_address()
    {
        var site = new AutoService { Key = "web:example.ru", Kind = AutoKind.Web, Name = "www.example.ru" };
        Assert.Equal("example.ru", AutoViewModel.NoSearchEntry(site));
        var server = new AutoService { Key = "tcp:x", Kind = AutoKind.Endpoint, Host = "vpn.example.org", Addresses = [new AutoAddress("192.0.2.1", DateTime.UtcNow)] };
        Assert.Equal("vpn.example.org", AutoViewModel.NoSearchEntry(server));
        Assert.Equal("192.0.2.1", AutoViewModel.NoSearchEntry(new AutoService { Kind = AutoKind.Endpoint, Addresses = [new AutoAddress("192.0.2.1", DateTime.UtcNow)] }));
    }

    [Fact]
    public void A_working_strategys_row_counts_its_failures_since_the_last_check_instead_of_the_last_failure_alone()
    {
        var was = Loc.Loc.I.English;
        try
        {
            Loc.Loc.I.English = false;
            var t0 = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
            var s = new AutoService
            {
                Key = "web:youtube.com", Status = AutoStatus.Applied, Strategy = "x", AppliedAt = t0, Why = "соединение есть, данных нет",
                Fails = [t0.AddMinutes(-1), t0.AddMinutes(1)], Oks = [t0.AddMinutes(2), t0.AddMinutes(3)],
            };
            // only what happened with the strategy on counts
            Assert.Equal("с обходом есть ошибки: не прошли 1 из 3 соединений, последняя — соединение есть, данных нет", AutoViewModel.AppliedDetail(s, t0.AddMinutes(6)));
            // the English page names the failure in English too
            Loc.Loc.I.English = true;
            Assert.Equal("errors with the bypass: 1 of 3 connections failed, the last — connected, no data", AutoViewModel.AppliedDetail(s, t0.AddMinutes(6)));
            Loc.Loc.I.English = false;
            // an hour later the window holds none of them
            Assert.Null(AutoViewModel.AppliedDetail(s, t0.AddHours(1)));
            // a check with the bypass passed since: the old failure is not shown
            s.CheckedAt = t0.AddMinutes(5);
            Assert.StartsWith("проверка с обходом прошла в ", AutoViewModel.AppliedDetail(s, t0.AddMinutes(6)), StringComparison.Ordinal);
            // pinned, or not applied: the row keeps its own text
            s.Pinned = true;
            Assert.Null(AutoViewModel.AppliedDetail(s, t0.AddMinutes(6)));
            s.Pinned = false;
            s.Status = AutoStatus.Degraded;
            Assert.Null(AutoViewModel.AppliedDetail(s, t0.AddMinutes(6)));
        }
        finally
        {
            Loc.Loc.I.English = was;
        }
    }
}
