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
}
