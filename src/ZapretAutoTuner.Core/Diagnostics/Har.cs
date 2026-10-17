using System.Globalization;
using System.Text.Json;

namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>
/// Reads a HAR 1.2 file (Playwright, Chrome DevTools, Firefox) into page requests, so a HAR the user saved in their
/// own browser can be analysed like our own page load (dpi-diagnostics §4).
/// </summary>
public static class Har
{
    public static PageLoad Parse(string json, string? url = null)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        var log = doc.RootElement.GetProperty("log");
        string browser = log.TryGetProperty("browser", out var b) && b.TryGetProperty("name", out var bn) ? bn.GetString() ?? "" : "";

        DateTimeOffset? pageStart = null;
        double? onLoad = null;
        if (log.TryGetProperty("pages", out var pages) && pages.ValueKind == JsonValueKind.Array && pages.GetArrayLength() > 0)
        {
            var p = pages[0];
            if (p.TryGetProperty("startedDateTime", out var sd) && TryDate(sd.GetString(), out var d))
                pageStart = d;
            if (p.TryGetProperty("pageTimings", out var pt) && pt.TryGetProperty("onLoad", out var ol) && ol.TryGetDouble(out var olv) && olv >= 0)
                onLoad = olv;
        }

        var requests = new List<PageRequest>();
        var altSvc = new List<string>();
        if (log.TryGetProperty("entries", out var entries))
        {
            foreach (var e in entries.EnumerateArray())
            {
                var req = e.GetProperty("request");
                var resp = e.TryGetProperty("response", out var r) ? r : default;
                string reqUrl = req.GetProperty("url").GetString() ?? "";
                int status = resp.ValueKind == JsonValueKind.Object && resp.TryGetProperty("status", out var st) && st.TryGetInt32(out var sv) ? sv : 0;
                string? failure = Str(resp, "_failureText") ?? Str(e, "_failureText") ?? Str(resp, "_error");
                double time = e.TryGetProperty("time", out var t) && t.TryGetDouble(out var tv) ? tv : -1;
                DateTimeOffset? started = e.TryGetProperty("startedDateTime", out var esd) && TryDate(esd.GetString(), out var ed) ? ed : null;
                pageStart ??= started;

                long bytes = 0;
                if (resp.ValueKind == JsonValueKind.Object)
                {
                    if (resp.TryGetProperty("content", out var c) && c.TryGetProperty("size", out var cs) && cs.TryGetInt64(out var csv) && csv > 0)
                        bytes = csv;
                    else if (resp.TryGetProperty("bodySize", out var bs) && bs.TryGetInt64(out var bsv) && bsv > 0)
                        bytes = bsv;
                    if (resp.TryGetProperty("headers", out var hs))
                    {
                        foreach (var h in hs.EnumerateArray())
                        {
                            if (string.Equals(Str(h, "name"), "alt-svc", StringComparison.OrdinalIgnoreCase))
                                altSvc.AddRange(AltSvcHosts(Str(h, "value") ?? ""));
                        }
                    }
                }

                // a response with status 0 and no error is a request the browser gave up on without saying why
                if (status <= 0 && failure is null)
                    failure = time < 0 ? null : "no response";
                requests.Add(new PageRequest
                {
                    Url = reqUrl,
                    Method = Str(req, "method") ?? "GET",
                    ResourceType = Str(e, "_resourceType") ?? Guess(resp),
                    Status = status > 0 ? status : null,
                    Error = failure,
                    Bytes = bytes,
                    Started = started is { } s && pageStart is { } ps ? s - ps : TimeSpan.Zero,
                    Duration = failure is null && time >= 0 ? TimeSpan.FromMilliseconds(time) : null,
                });
            }
        }

        return new PageLoad
        {
            Url = url ?? requests.FirstOrDefault(r => r.ResourceType == "document")?.Url ?? requests.FirstOrDefault()?.Url ?? "",
            Browser = browser.Length > 0 ? browser.ToLowerInvariant() : "har",
            LoadFired = onLoad is not null,
            LoadTime = onLoad is { } l ? TimeSpan.FromMilliseconds(l) : null,
            Requests = requests,
            AltSvc = altSvc.Distinct().ToList(),
        };
    }

    /// <summary>Hosts from an Alt-Svc value such as <c>h3="alt.example:443"; ma=86400, h3=":443"</c>.</summary>
    public static IEnumerable<string> AltSvcHosts(string value)
    {
        foreach (var part in value.Split(','))
        {
            int q1 = part.IndexOf('"', StringComparison.Ordinal);
            int q2 = q1 < 0 ? -1 : part.IndexOf('"', q1 + 1);
            if (q2 < 0)
                continue;
            var authority = part[(q1 + 1)..q2];
            int colon = authority.LastIndexOf(':');
            var host = colon >= 0 ? authority[..colon] : authority;
            if (host.Length > 0)
                yield return host.Trim('[', ']').ToLowerInvariant();
        }
    }

    private static string Guess(JsonElement resp)
    {
        if (resp.ValueKind != JsonValueKind.Object || !resp.TryGetProperty("content", out var c))
            return "other";
        var mime = Str(c, "mimeType") ?? "";
        return mime switch
        {
            _ when mime.Contains("html", StringComparison.OrdinalIgnoreCase) => "document",
            _ when mime.Contains("javascript", StringComparison.OrdinalIgnoreCase) => "script",
            _ when mime.Contains("css", StringComparison.OrdinalIgnoreCase) => "stylesheet",
            _ when mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase) => "image",
            _ when mime.StartsWith("font/", StringComparison.OrdinalIgnoreCase) || mime.Contains("woff", StringComparison.OrdinalIgnoreCase) => "font",
            _ when mime.StartsWith("video/", StringComparison.OrdinalIgnoreCase) || mime.StartsWith("audio/", StringComparison.OrdinalIgnoreCase) => "media",
            _ when mime.Contains("json", StringComparison.OrdinalIgnoreCase) => "fetch",
            _ => "other",
        };
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static bool TryDate(string? s, out DateTimeOffset d) =>
        DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out d);
}
