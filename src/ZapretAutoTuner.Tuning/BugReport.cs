using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using ZapretAutoTuner.Core;
using ZapretAutoTuner.Core.Diagnostics;
using ZapretAutoTuner.Delivery;

namespace ZapretAutoTuner.Tuning;

/// <summary>What went wrong, as the program saw it.</summary>
public enum BugKind
{
    /// <summary>An exception or a crash of AutoTuner itself.</summary>
    AppError,

    /// <summary>The engine refused a strategy that passed the Validator (a gap in the Validator or the catalog).</summary>
    EngineRefused,

    /// <summary>The Validator, a skill and the engine's sources disagree.</summary>
    ValidatorMismatch,

    /// <summary>A tuning run found nothing on a blocked resource.</summary>
    TuningFailed,

    /// <summary>zapret-gui's API answered with an error.</summary>
    ZapretGuiError,

    /// <summary>The engine itself crashed (segfault, abort).</summary>
    EngineCrash,

    /// <summary>The engine behaves differently from its documentation.</summary>
    EngineBehaviour,
}

/// <summary>Where an issue is filed.</summary>
public enum BugTarget
{
    AutoTuner,
    ZapretGui,
    Zapret2,
}

/// <summary>Everything the draft is built from; the description fields are the user's own words.</summary>
public sealed record BugReportInput
{
    public BugKind Kind { get; init; }

    /// <summary>One line on what happened: the refusal text, the mismatch, the failed run.</summary>
    public string? Summary { get; init; }

    public Exception? Exception { get; init; }

    public string WhatDid { get; init; } = "";

    public string Expected { get; init; } = "";

    public string Got { get; init; } = "";

    /// <summary>zapret-gui's version when the router side is involved and known.</summary>
    public string? ZapretGuiVersion { get; init; }

    /// <summary>Extra environment lines (VM, antivirus, router model).</summary>
    public IReadOnlyList<string> Environment { get; init; } = [];

    /// <summary>The program's event log; only the tail goes in.</summary>
    public IReadOnlyList<string> EventLog { get; init; } = [];

    /// <summary>The engine's --debug output; only the tail goes in.</summary>
    public IReadOnlyList<string> EngineLog { get; init; } = [];

    public IReadOnlyList<string>? Argv { get; init; }

    public ClassifierVerdict? Verdict { get; init; }

    /// <summary>The file name of the "Собрать отчёт" archive the user attaches (never its content).</summary>
    public string? ArchiveName { get; init; }

    /// <summary>Replace domains with d1, d2… (addresses are masked always).</summary>
    public bool MaskDomains { get; init; }

    /// <summary>Domains to mask besides the ones found in the verdict and the argv.</summary>
    public IReadOnlyList<string> Domains { get; init; } = [];

    /// <summary>The UI language: the template's language.</summary>
    public bool Russian { get; init; } = true;

    public int MaxLogLines { get; init; } = 60;
}

public sealed record BugTargetSuggestion(BugTarget Target, string Repository, string ReasonRu, string ReasonEn)
{
    public string Reason(bool russian) => russian ? ReasonRu : ReasonEn;
}

/// <param name="Body">The full Markdown text the user reviews, edits and pastes.</param>
/// <param name="IssueUrl">GitHub's "new issue" page with the title and a body that fits the URL limit.</param>
/// <param name="UrlShortened">The body in the URL lost log lines: the user pastes the full text and attaches the archive.</param>
/// <param name="Notice">What to tell the user next to the button.</param>
public sealed record BugReportDraft(string Title, string Body, BugTargetSuggestion Target, string IssueUrl, bool UrlShortened, string Notice);

/// <summary>
/// "Сообщить о проблеме" (PLAN 4a.6): a draft issue with what the user did, expected and got, the versions and the
/// debug data (event log and engine log tails, argv, classifier verdict, the report archive to attach), addresses always
/// masked and domains on request, a suggestion where to file it, and GitHub's new-issue link with the fields filled.
/// Nothing is sent by this code: the user reads, edits and submits the page himself.
/// </summary>
public static partial class BugReport
{
    /// <summary>GitHub refuses longer new-issue URLs (about 8 KB); a margin is kept.</summary>
    public const int MaxUrlLength = 8000;

    public const int MaxTitleLength = 120;

    public static string Repository(BugTarget t) => t switch
    {
        BugTarget.ZapretGui => "avatarDD/zapret-gui",
        BugTarget.Zapret2 => "bol-van/zapret2",
        _ => "avatarDD/Zapret2_AutoTuner",
    };

    [GeneratedRegex(@"Segmentation fault|SIGSEGV|SIGABRT|core dumped|Assertion .* failed|stack smashing|double free", RegexOptions.IgnoreCase)]
    private static partial Regex EngineCrashRe();

    /// <summary>Where the issue belongs, with a short reason.</summary>
    public static BugTargetSuggestion SuggestTarget(BugReportInput i)
    {
        BugTargetSuggestion S(BugTarget t, string ru, string en) => new(t, Repository(t), ru, en);
        if (i.Kind == BugKind.EngineCrash || (i.Kind is BugKind.EngineRefused or BugKind.TuningFailed && i.EngineLog.Any(l => EngineCrashRe().IsMatch(l))))
            return S(BugTarget.Zapret2, "движок nfqws2/winws2 упал: это ошибка zapret2, приложите argv и лог движка",
                "the nfqws2/winws2 engine crashed: that is a zapret2 bug, attach the argv and the engine log");
        if (i.Kind == BugKind.EngineBehaviour)
            return S(BugTarget.Zapret2, "движок ведёт себя не так, как написано в его документации: вопрос к zapret2",
                "the engine behaves differently from its documentation: a question for zapret2");
        if (i.Kind == BugKind.ZapretGuiError || i.Exception is ZapretGuiException || i.Exception?.InnerException is ZapretGuiException)
            return S(BugTarget.ZapretGui, "ошибку вернул API zapret-gui на роутере", "the error came from zapret-gui's API on the router");
        return i.Kind switch
        {
            BugKind.EngineRefused => S(BugTarget.AutoTuner, "Validator AutoTuner пропустил стратегию, которую движок отклонил: нужно исправить проверку",
                "the AutoTuner Validator let through a strategy the engine refused: the check needs fixing"),
            BugKind.ValidatorMismatch => S(BugTarget.AutoTuner, "проверка AutoTuner расходится со skill или исходниками zapret2", "the AutoTuner check disagrees with a skill or the zapret2 sources"),
            BugKind.TuningFailed => S(BugTarget.AutoTuner, "подбор не нашёл стратегию: разбирается в AutoTuner (приложите архив отчёта)",
                "the search found no strategy: AutoTuner looks into it (attach the report archive)"),
            _ => S(BugTarget.AutoTuner, "ошибка в самой программе AutoTuner", "an error in AutoTuner itself"),
        };
    }

    /// <summary>The draft for the suggested target or the one the user picked.</summary>
    public static BugReportDraft Build(BugReportInput input, BugTarget? target = null)
    {
        var suggestion = SuggestTarget(input);
        if (target is { } t && t != suggestion.Target)
            suggestion = new BugTargetSuggestion(t, Repository(t), "выбрано пользователем", "chosen by the user");
        var mask = new FailureReport.Masker(input.MaskDomains);
        foreach (var d in Domains(input))
            mask.Domain(d);

        var title = Title(input, mask);
        var body = Body(input, suggestion, mask, input.MaxLogLines, null);
        bool ru = input.Russian;
        var url = NewIssueUrl(suggestion.Target, title, body);
        bool shortened = false;
        if (url.Length > MaxUrlLength)
        {
            shortened = true;
            var note = ru
                ? $"Логи в ссылке сокращены: замените текст заявки полным текстом из AutoTuner{(input.ArchiveName is null ? "" : $" и приложите архив {input.ArchiveName}")}."
                : $"The logs in the link are shortened: replace the issue text with the full text from AutoTuner{(input.ArchiveName is null ? "" : $" and attach the archive {input.ArchiveName}")}.";
            foreach (var lines in new[] { 20, 8, 3, 0 })
            {
                url = NewIssueUrl(suggestion.Target, title, Body(input, suggestion, mask, lines, note));
                if (url.Length <= MaxUrlLength)
                    break;
            }
            if (url.Length > MaxUrlLength)
                url = NewIssueUrl(suggestion.Target, title, Cut(Body(input, suggestion, mask, 0, note), suggestion.Target, title));
        }
        var notice = (ru
            ? $"Куда: {suggestion.Repository} — {suggestion.ReasonRu}. Ничего не отправляется само: проверьте текст и отправьте заявку на странице GitHub."
            : $"Where: {suggestion.Repository} — {suggestion.ReasonEn}. Nothing is sent by itself: check the text and submit the issue on the GitHub page.")
            + (shortened
                ? ru ? " Текст не поместился в ссылку целиком: скопируйте полный текст и вставьте его в заявку." : " The text did not fit into the link: copy the full text and paste it into the issue."
                : "")
            + (input.ArchiveName is null ? "" : ru ? $" Приложите архив {input.ArchiveName} сами." : $" Attach the archive {input.ArchiveName} yourself.");
        return new BugReportDraft(title, body, suggestion, url, shortened, notice);
    }

    /// <summary>GitHub's new-issue page with the title and body prefilled.</summary>
    public static string NewIssueUrl(BugTarget target, string title, string body) =>
        $"https://github.com/{Repository(target)}/issues/new?title={Uri.EscapeDataString(title)}&body={Uri.EscapeDataString(body)}";

    private static IEnumerable<string> Domains(BugReportInput i)
    {
        var list = new List<string>(i.Domains);
        if (i.Verdict is { } v)
            list.Add(v.Host);
        foreach (var a in i.Argv ?? [])
        {
            foreach (var key in new[] { "--hostlist-domains=", "--hostlist-exclude-domains=" })
            {
                if (a.StartsWith(key, StringComparison.Ordinal))
                    list.AddRange(a[key.Length..].Split(',', StringSplitOptions.RemoveEmptyEntries).Select(d => d.TrimStart('^')));
            }
            if (a.StartsWith("--lua-desync=", StringComparison.Ordinal) && Regex.Match(a, "sni=([A-Za-z0-9.-]+)") is { Success: true } m)
                list.Add(m.Groups[1].Value);
        }
        // longest first, so a parent domain does not eat part of a subdomain when lines are masked
        return list.Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(d => d.Length);
    }

    private static string Title(BugReportInput i, FailureReport.Masker mask)
    {
        bool ru = i.Russian;
        var what = i.Kind switch
        {
            BugKind.EngineRefused => ru ? "Движок отклонил стратегию" : "The engine refused a strategy",
            BugKind.ValidatorMismatch => ru ? "Расхождение Validator и движка" : "Validator and engine disagree",
            BugKind.TuningFailed => ru ? "Подбор не нашёл стратегию" : "The search found no strategy",
            BugKind.ZapretGuiError => ru ? "Ошибка API zapret-gui" : "zapret-gui API error",
            BugKind.EngineCrash => ru ? "Падение движка" : "Engine crash",
            BugKind.EngineBehaviour => ru ? "Поведение движка расходится с документацией" : "Engine behaviour differs from the docs",
            _ => ru ? "Ошибка программы" : "Application error",
        };
        var detail = i.Summary ?? i.Exception?.Message ?? (i.Kind == BugKind.TuningFailed && i.Verdict is { } v ? $"{v.Host}: {v.Primary}" : null);
        var title = detail is null ? what : $"{what}: {Clean(mask.Line(HideHome(detail)))}";
        return title.Length > MaxTitleLength ? title[..(MaxTitleLength - 1)] + "…" : title;
    }

    private static string Clean(string s) => Regex.Replace(s.ReplaceLineEndings(" "), "\\s+", " ").Trim();

    private static string Body(BugReportInput i, BugTargetSuggestion target, FailureReport.Masker mask, int logLines, string? note)
    {
        bool ru = i.Russian;
        string M(string s) => mask.Line(HideHome(s));
        var sb = new StringBuilder();
        void H(string ruText, string enText) => sb.Append("\n## ").Append(ru ? ruText : enText).Append("\n\n");
        void Text(string s) => sb.Append(s.Trim().Length == 0 ? (ru ? "_не заполнено_" : "_not filled in_") : M(s.Trim())).Append('\n');
        void Code(IEnumerable<string> lines)
        {
            sb.Append("```\n");
            foreach (var l in lines)
                sb.Append(M(l).Replace("```", "'''", StringComparison.Ordinal)).Append('\n');
            sb.Append("```\n");
        }

        if (note is not null)
            sb.Append("> ").Append(note).Append('\n');
        H("Что произошло", "What happened");
        sb.Append(ru ? "Тип: " : "Kind: ").Append(i.Kind).Append('\n');
        if (i.Summary is { Length: > 0 } summary)
            sb.Append(M(summary)).Append('\n');
        if (i.Exception is { } e)
            sb.Append('`').Append(e.GetType().FullName).Append(": ").Append(M(Clean(e.Message))).Append("`\n");
        H("Что делал", "What I did");
        Text(i.WhatDid);
        H("Что ожидал", "What I expected");
        Text(i.Expected);
        H("Что получилось", "What I got");
        Text(i.Got);

        H("Версии", "Versions");
        sb.Append(CultureInfo.InvariantCulture, $"- {AppInfo.Name}: {AppInfo.Version}\n");
        sb.Append(CultureInfo.InvariantCulture, $"- zapret2: {AppInfo.Zapret2Version} (lua compat {AppInfo.LuaCompatVersion})\n");
        sb.Append(CultureInfo.InvariantCulture, $"- {(ru ? "ОС" : "OS")}: {RuntimeInformation.OSDescription} ({RuntimeInformation.OSArchitecture}), .NET {System.Environment.Version}\n");
        sb.Append(CultureInfo.InvariantCulture, $"- zapret-gui: {i.ZapretGuiVersion ?? (ru ? "неизвестно / не используется" : "unknown / not used")}\n");
        foreach (var env in i.Environment)
            sb.Append("- ").Append(M(env)).Append('\n');

        H("Куда подаётся", "Where this goes");
        sb.Append(target.Repository).Append(" — ").Append(target.Reason(ru)).Append('\n');

        H("Отладочная информация", "Debug information");
        if (i.Verdict is { } v)
        {
            sb.Append(ru ? "**Вердикт классификатора:** " : "**Classifier verdict:** ")
                .Append(M(mask.Domain(v.Host))).Append(": ").Append(v.Primary).Append(" → ").Append(v.Next).Append('\n');
            foreach (var f in v.Findings)
                sb.Append("- ").Append(f.Label).Append(f.Address is null ? "" : " @ " + mask.Address(f.Address)).Append(": ").Append(M(string.Join("; ", f.Evidence))).Append('\n');
            sb.Append('\n');
        }
        if (i.Argv is { Count: > 0 } argv)
        {
            sb.Append("**argv:**\n");
            Code([Core.Engine.EngineArgsBuilder.ToCommandLine(argv)]);
            sb.Append('\n');
        }
        if (i.Exception is { } ex)
        {
            sb.Append(ru ? "**Исключение:**\n" : "**Exception:**\n");
            Code(ex.ToString().ReplaceLineEndings("\n").Split('\n').Take(Math.Clamp(logLines, 3, 40)));
            sb.Append('\n');
        }
        Tail(ru ? "Журнал событий" : "Event log", i.EventLog);
        Tail(ru ? "Лог движка" : "Engine log", i.EngineLog);
        if (i.ArchiveName is { } archive)
            sb.Append(ru ? $"**Архив отчёта:** приложите файл `{archive}` (кнопка «Собрать отчёт»).\n" : $"**Report archive:** attach the file `{archive}` (the \"Collect report\" button).\n");

        sb.Append("\n---\n");
        sb.Append(ru
            ? $"_IP-адреса замаскированы{(i.MaskDomains ? ", домены заменены на d1, d2…" : "")}. Черновик подготовлен {AppInfo.Name}; ничего не отправлено автоматически._\n"
            : $"_IP addresses are masked{(i.MaskDomains ? ", domains replaced with d1, d2…" : "")}. Draft prepared by {AppInfo.Name}; nothing was sent automatically._\n");
        return sb.ToString().TrimStart('\n');

        void Tail(string head, IReadOnlyList<string> log)
        {
            if (log.Count == 0)
                return;
            var shown = log.TakeLast(logLines).ToList();
            sb.Append("**").Append(head).Append(ru ? $" (последние {shown.Count} из {log.Count} строк):**\n" : $" (last {shown.Count} of {log.Count} lines):**\n");
            if (shown.Count > 0)
                Code(shown);
            sb.Append('\n');
        }
    }

    /// <summary>The body cut so the whole URL fits, at a line boundary, with an end marker.</summary>
    private static string Cut(string body, BugTarget target, string title)
    {
        const string marker = "\n…\n";
        int lo = 0, hi = body.Length;
        while (lo < hi)
        {
            int mid = (lo + hi + 1) / 2;
            if (NewIssueUrl(target, title, body[..mid] + marker).Length <= MaxUrlLength)
                lo = mid;
            else
                hi = mid - 1;
        }
        var cut = body[..lo];
        int nl = cut.LastIndexOf('\n');
        if (nl > 0)
            cut = cut[..nl];
        return cut + marker;
    }

    /// <summary>The user's home folder in paths (stack traces, logs) becomes <c>~</c>: it often holds the user name.</summary>
    private static string HideHome(string s)
    {
        var home = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
        if (home.Length < 3)
            return s;
        s = s.Replace(home, "~", StringComparison.OrdinalIgnoreCase);
        return s.Replace(home.Replace('\\', '/'), "~", StringComparison.OrdinalIgnoreCase);
    }
}
