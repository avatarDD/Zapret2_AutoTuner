using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Storage;

/// <summary>
/// A change journal reason in both UI languages, kept in the existing <c>change_journal.reason</c> text as
/// <c>{"ru":…,"en":…}</c>. Rows written before that hold plain text, which reads back the same in both languages.
/// </summary>
public static class JournalReason
{
    public static string Encode(string ru, string en) => new JsonObject { ["ru"] = ru, ["en"] = en }.ToJsonString();

    public static (string Ru, string En) Decode(string? stored)
    {
        var s = stored ?? "";
        if (s.StartsWith('{'))
        {
            try
            {
                if (JsonNode.Parse(s) is JsonObject o && o["ru"] is JsonValue ru && ru.TryGetValue<string>(out var r))
                    return (r, o["en"] is JsonValue en && en.TryGetValue<string>(out var e) ? e : r);
            }
            catch (JsonException)
            {
            }
        }
        return (s, s);
    }
}
