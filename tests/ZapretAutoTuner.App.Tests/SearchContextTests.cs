using ZapretAutoTuner.App.Services;

namespace ZapretAutoTuner.App.Tests;

public sealed class SearchContextTests
{
    [Theory]
    [InlineData("AS12389", 12389)]
    [InlineData(" as 12389 ", 12389)]
    [InlineData("12389", 12389)]
    [InlineData("", null)]
    [InlineData("AS", null)]
    [InlineData("Rostelecom", null)]
    [InlineData("-5", null)]
    [InlineData("0", null)]
    public void Provider_asn_is_parsed_from_what_the_user_typed(string text, int? asn) =>
        Assert.Equal(asn, SearchContext.ParseAsn(text));

    [Fact]
    public async Task Learning_is_on_by_default_and_follows_the_setting()
    {
        var dir = Directory.CreateTempSubdirectory("ztapp").FullName;
        try
        {
            var host = new AppHost(dir);
            try
            {
                Assert.True(host.Settings.Learning);
                var on = SearchContext.For(host, "SniBlock");
                Assert.NotNull(on.Learning);
                Assert.Equal("SniBlock", on.Learning.Context.Label);
                Assert.Null(on.Asn);
                Assert.Null(on.NetworkId);

                host.Settings.ProviderAsn = "AS64500";
                var withAsn = SearchContext.For(host);
                Assert.Equal(64500, withAsn.Asn);
                Assert.NotNull(withAsn.NetworkId);
                Assert.Equal(64500, withAsn.Learning?.Context.Asn);

                host.Settings.Learning = false;
                Assert.Null(SearchContext.For(host).Learning);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, true);
        }
    }
}
