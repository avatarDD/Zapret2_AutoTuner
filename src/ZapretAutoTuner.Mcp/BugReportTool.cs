using System.Text.Json.Nodes;
using ZapretAutoTuner.Tuning;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// <c>bug_report_draft</c> (PLAN 4a.6): the issue draft "Сообщить о проблеме" builds, as text and GitHub's prefilled
/// new-issue link. Nothing is opened or sent: the model shows the draft, the user submits it himself.
/// </summary>
public static class BugReportTool
{
    private static readonly string[] Kinds = ["app_error", "engine_refused", "validator_mismatch", "tuning_failed", "zapret_gui_error", "engine_crash", "engine_behaviour"];
    private static readonly string[] Trackers = ["autotuner", "zapret_gui", "zapret2"];

    public static McpToolDefinition Definition { get; } = new("bug_report_draft", McpScope.Read,
        "Drafts an issue about a problem found in AutoTuner, zapret-gui or zapret2: the fixed template with versions, the classifier's verdict, the event log tail, addresses always masked (domains on request), a suggestion where to file it and GitHub's new-issue link. Returns text only: nothing is opened or sent; show it to the user, who reviews and submits it (or uses Reports → Report a problem in AutoTuner).",
        S.Obj([
            ("kind", S.Str("What went wrong", values: Kinds)),
            ("summary", S.Str("One line on what happened", 300)),
            ("what_did", S.Str("What was done", 2000)),
            ("expected", S.Str("What was expected", 2000)),
            ("got", S.Str("What happened instead", 2000)),
            ("about", S.Str("A target from targets_list whose diagnosis goes in", 253, McpTools.HostPattern)),
            ("tracker", S.Str("Where to file it (default: suggested)", values: Trackers)),
            ("mask_domains", S.Bool("Replace domains with d1, d2… (addresses are masked always)")),
            ("language", S.Str("Template language (default ru)", values: ["ru", "en"])),
        ], "kind"));

    public static JsonObject Draft(McpSession session, JsonObject a)
    {
        var about = (string?)a["about"];
        if (about is not null && !session.IsTarget(about))
            return McpErrors.NotATarget(about);
        var kind = (BugKind)Array.IndexOf(Kinds, (string)a["kind"]!);
        var context = session.Host.BugReportContext();
        var input = context with
        {
            Kind = kind,
            Summary = (string?)a["summary"] ?? context.Summary,
            WhatDid = (string?)a["what_did"] ?? context.WhatDid,
            Expected = (string?)a["expected"] ?? context.Expected,
            Got = (string?)a["got"] ?? context.Got,
            Verdict = about is null ? context.Verdict : session.Verdict(about) ?? context.Verdict,
            Domains = [.. context.Domains, .. session.Host.Targets],
            MaskDomains = (bool?)a["mask_domains"] ?? false,
            Russian = (string?)a["language"] != "en",
        };
        BugTarget? target = (string?)a["tracker"] is { } t ? (BugTarget)Array.IndexOf(Trackers, t) : null;
        var d = BugReport.Build(input, target);
        var body = d.Body.Length > ResourceTools.MaxTextChars ? d.Body[..ResourceTools.MaxTextChars] : d.Body;
        return new JsonObject
        {
            ["ok"] = true,
            ["title"] = d.Title,
            ["body"] = body,
            ["body_truncated"] = body.Length < d.Body.Length ? true : null,
            ["repository"] = d.Target.Repository,
            ["tracker"] = Trackers[(int)d.Target.Target],
            ["reason"] = d.Target.ReasonEn,
            ["issue_url"] = d.IssueUrl,
            ["url_shortened"] = d.UrlShortened,
            ["notice"] = d.Notice,
            ["sent"] = false,
            ["hint"] = "nothing was opened or sent: show the draft to the user; they edit and submit it themselves",
        };
    }
}
