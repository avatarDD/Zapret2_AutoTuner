using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Tuning.Tests;

/// <summary>"Сообщить о проблеме" (PLAN 4a.6): template, masking, target and URL limits.</summary>
public sealed class BugReportTests
{
    private static BugReportInput Refused(bool russian = true, bool maskDomains = false) => new()
    {
        Kind = BugKind.EngineRefused,
        Summary = "blob 'zt_x' unavailable at 203.0.113.7",
        WhatDid = "Подбирал стратегию для youtube.com",
        Expected = "Движок запустится",
        Got = "Движок вышел с ошибкой, мой адрес 192.168.1.10",
        Argv = ["--qnum=300", "--filter-tcp=443", "--hostlist-domains=youtube.com,googlevideo.com", "--lua-desync=fake:blob=zt_x:tcp_md5"],
        EngineLog = [.. Enumerable.Range(1, 100).Select(i => $"line {i} to 2001:db8:1:2::5 for youtube.com")],
        EventLog = ["started", "connect 10.0.0.2"],
        Verdict = new ClassifierVerdict
        {
            Host = "youtube.com",
            Primary = BlockLabel.SniBlock,
            Next = NextStep.SearchStrategy,
            Findings = [new LabelFinding(BlockLabel.SniBlock, "142.250.1.1", ["RST after ClientHello"])],
        },
        ArchiveName = "autotuner-report-2026-10-22.zip",
        Russian = russian,
        MaskDomains = maskDomains,
        ZapretGuiVersion = "2.4.0",
    };

    [Fact]
    public void Template_has_every_section_in_the_ui_language()
    {
        var ru = BugReport.Build(Refused());
        foreach (var head in new[] { "## Что произошло", "## Что делал", "## Что ожидал", "## Что получилось", "## Версии", "## Куда подаётся", "## Отладочная информация" })
            Assert.Contains(head, ru.Body, StringComparison.Ordinal);
        Assert.Contains("zapret2: 1.0.5.2", ru.Body, StringComparison.Ordinal);
        Assert.Contains("zapret-gui: 2.4.0", ru.Body, StringComparison.Ordinal);
        Assert.Contains("**argv:**", ru.Body, StringComparison.Ordinal);
        Assert.Contains("SniBlock", ru.Body, StringComparison.Ordinal);
        Assert.Contains("последние 60 из 100 строк", ru.Body, StringComparison.Ordinal);
        Assert.Contains("autotuner-report-2026-10-22.zip", ru.Body, StringComparison.Ordinal);
        Assert.StartsWith("Движок отклонил стратегию: blob 'zt_x' unavailable", ru.Title, StringComparison.Ordinal);

        var en = BugReport.Build(Refused(russian: false) with { WhatDid = "" });
        foreach (var head in new[] { "## What happened", "## What I did", "## What I expected", "## What I got", "## Versions", "## Where this goes", "## Debug information" })
            Assert.Contains(head, en.Body, StringComparison.Ordinal);
        Assert.Contains("_not filled in_", en.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("## Что", en.Body, StringComparison.Ordinal);
        Assert.StartsWith("The engine refused a strategy", en.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void Addresses_are_always_masked_domains_on_request()
    {
        var d = BugReport.Build(Refused());
        Assert.DoesNotContain("192.168.1.10", d.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("10.0.0.2", d.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("203.0.113.7", d.Body + d.Title, StringComparison.Ordinal);
        Assert.DoesNotContain("142.250.1.1", d.Body, StringComparison.Ordinal);
        Assert.Contains("142.250.1.x", d.Body, StringComparison.Ordinal);
        Assert.Contains("youtube.com", d.Body, StringComparison.Ordinal);

        var masked = BugReport.Build(Refused(maskDomains: true));
        Assert.DoesNotContain("youtube.com", masked.Body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("googlevideo.com", masked.Body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("домены заменены", masked.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("youtube.com", Uri.UnescapeDataString(masked.IssueUrl), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(BugKind.AppError, BugTarget.AutoTuner)]
    [InlineData(BugKind.EngineRefused, BugTarget.AutoTuner)]
    [InlineData(BugKind.ValidatorMismatch, BugTarget.AutoTuner)]
    [InlineData(BugKind.TuningFailed, BugTarget.AutoTuner)]
    [InlineData(BugKind.ZapretGuiError, BugTarget.ZapretGui)]
    [InlineData(BugKind.EngineCrash, BugTarget.Zapret2)]
    [InlineData(BugKind.EngineBehaviour, BugTarget.Zapret2)]
    public void Suggests_where_to_file(BugKind kind, BugTarget target)
    {
        var s = BugReport.SuggestTarget(new BugReportInput { Kind = kind });
        Assert.Equal(target, s.Target);
        Assert.Equal(BugReport.Repository(target), s.Repository);
        Assert.NotEmpty(s.ReasonRu);
        Assert.NotEmpty(s.ReasonEn);
    }

    [Fact]
    public void Evidence_overrides_the_kind_and_the_user_can_pick()
    {
        Assert.Equal(BugTarget.ZapretGui, BugReport.SuggestTarget(new BugReportInput { Kind = BugKind.AppError, Exception = new ZapretGuiException("POST /api/lua/create: 500") }).Target);
        Assert.Equal(BugTarget.Zapret2, BugReport.SuggestTarget(new BugReportInput { Kind = BugKind.EngineRefused, EngineLog = ["nfqws2: Segmentation fault (core dumped)"] }).Target);
        var picked = BugReport.Build(Refused(), BugTarget.Zapret2);
        Assert.Equal("bol-van/zapret2", picked.Target.Repository);
        Assert.StartsWith("https://github.com/bol-van/zapret2/issues/new?title=", picked.IssueUrl, StringComparison.Ordinal);
    }

    [Fact]
    public void Exception_goes_in_with_type_and_trace()
    {
        Exception e;
        try
        {
            throw new InvalidOperationException("boom at 192.168.0.5");
        }
        catch (InvalidOperationException x)
        {
            e = x;
        }
        var d = BugReport.Build(new BugReportInput { Kind = BugKind.AppError, Exception = e, Russian = false });
        Assert.Contains("System.InvalidOperationException: boom at lan-", d.Body, StringComparison.Ordinal);
        Assert.Contains("**Exception:**", d.Body, StringComparison.Ordinal);
        Assert.Contains("Exception_goes_in_with_type_and_trace", d.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("192.168.0.5", d.Body + d.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void Long_logs_are_cut_from_the_url_not_from_the_text()
    {
        var big = Refused() with { EngineLog = [.. Enumerable.Range(1, 2000).Select(i => $"строка лога движка номер {i} с длинным хвостом текста")], MaxLogLines = 300 };
        var d = BugReport.Build(big);
        Assert.True(d.UrlShortened);
        Assert.True(d.IssueUrl.Length <= BugReport.MaxUrlLength, d.IssueUrl.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Contains("строка лога движка номер 2000", d.Body, StringComparison.Ordinal); // the full text keeps the tail
        Assert.Contains("последние 300 из 2000", d.Body, StringComparison.Ordinal);
        var urlBody = Uri.UnescapeDataString(d.IssueUrl[(d.IssueUrl.IndexOf("&body=", StringComparison.Ordinal) + 6)..]);
        Assert.StartsWith("> Логи в ссылке сокращены", urlBody, StringComparison.Ordinal);
        Assert.Contains("autotuner-report-2026-10-22.zip", urlBody, StringComparison.Ordinal);
        Assert.Contains("скопируйте полный текст", d.Notice, StringComparison.Ordinal);

        // even a huge description fits: the body in the URL is cut at a line
        var huge = Refused() with { Got = string.Join("\n", Enumerable.Repeat("очень длинное описание проблемы", 800)) };
        var h = BugReport.Build(huge);
        Assert.True(h.IssueUrl.Length <= BugReport.MaxUrlLength);
        Assert.EndsWith(Uri.EscapeDataString("\n…\n"), h.IssueUrl, StringComparison.Ordinal);

        var small = BugReport.Build(new BugReportInput { Kind = BugKind.AppError, Summary = "x" });
        Assert.False(small.UrlShortened);
        Assert.Contains("Nothing is sent", BugReport.Build(new BugReportInput { Kind = BugKind.AppError, Russian = false }).Notice, StringComparison.Ordinal);
    }
}
