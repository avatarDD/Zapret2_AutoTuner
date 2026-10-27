namespace ZapretAutoTuner.Storage.Tests;

public sealed class JournalReasonTests
{
    [Fact]
    public void Both_languages_round_trip_through_the_reason_text()
    {
        var stored = JournalReason.Encode("сайт открывается без обхода", "the site opens without bypass");
        Assert.Equal(("сайт открывается без обхода", "the site opens without bypass"), JournalReason.Decode(stored));
    }

    [Theory]
    [InlineData("пользователь отказался / the user declined")]
    [InlineData("{не json")]
    [InlineData("{\"x\":1}")]
    [InlineData("")]
    public void Old_plain_rows_read_the_same_in_both_languages(string old)
    {
        Assert.Equal((old, old), JournalReason.Decode(old));
    }

    [Fact]
    public void A_reason_in_the_journal_keeps_both_languages()
    {
        var path = Path.Combine(Path.GetTempPath(), "zt-journal-" + Guid.NewGuid().ToString("N") + ".db");
        try
        {
            using (var kb = KnowledgeBase.Open(path))
            {
                kb.AddChange("example.com", "degraded", JournalReason.Encode("неудач 4/5", "failures 4/5"));
                var (ru, en) = JournalReason.Decode(kb.Changes(1)[0].Reason);
                Assert.Equal("неудач 4/5", ru);
                Assert.Equal("failures 4/5", en);
            }
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            File.Delete(path);
        }
    }
}
