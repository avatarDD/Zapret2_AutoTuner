namespace ZapretAutoTuner.Core.Diagnostics;

/// <summary>One request the browser made while opening a page (from the network log or a HAR).</summary>
public sealed record PageRequest
{
    public required string Url { get; init; }

    public string Host => Uri.TryCreate(Url, UriKind.Absolute, out var u) ? u.IdnHost.ToLowerInvariant() : "";

    public string Method { get; init; } = "GET";

    /// <summary>Browser resource type: document, script, stylesheet, image, font, xhr, fetch, media, websocket, ping, other…</summary>
    public string ResourceType { get; init; } = "other";

    /// <summary>HTTP status, null when no response came.</summary>
    public int? Status { get; init; }

    /// <summary>The browser's error text, such as <c>net::ERR_CONNECTION_RESET</c>; null on success.</summary>
    public string? Error { get; init; }

    /// <summary>Response body bytes received.</summary>
    public long Bytes { get; init; }

    /// <summary>When the request started, from the start of the navigation.</summary>
    public TimeSpan Started { get; init; }

    /// <summary>How long it took; null when it never finished (stalled).</summary>
    public TimeSpan? Duration { get; init; }

    public bool Finished => Error is not null || Duration is not null;
}

/// <summary>What a browser saw opening a page (PLAN 2.4, dpi-diagnostics §3 L3 and §4).</summary>
public sealed record PageLoad
{
    public required string Url { get; init; }

    public string Browser { get; init; } = "chromium";

    /// <summary>The <c>load</c> event fired before the timeout.</summary>
    public bool LoadFired { get; init; }

    public TimeSpan? LoadTime { get; init; }

    public TimeSpan Duration { get; init; }

    public IReadOnlyList<PageRequest> Requests { get; init; } = [];

    /// <summary>Hosts from <c>&lt;link rel=preconnect|dns-prefetch&gt;</c>: the page will need them soon.</summary>
    public IReadOnlyList<string> Hints { get; init; } = [];

    /// <summary>WebSocket URLs the page opened.</summary>
    public IReadOnlyList<string> WebSockets { get; init; } = [];

    /// <summary>Hosts announced in <c>Alt-Svc</c> headers (another host for HTTP/3).</summary>
    public IReadOnlyList<string> AltSvc { get; init; } = [];

    /// <summary>Navigation error (main document did not load), null otherwise.</summary>
    public string? Error { get; init; }

    public string? HarPath { get; init; }

    public string? ScreenshotPath { get; init; }
}
