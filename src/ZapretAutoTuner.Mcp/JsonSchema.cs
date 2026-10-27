using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ZapretAutoTuner.Mcp;

/// <summary>
/// The small JSON Schema subset the tools use (object, string, integer, boolean, array; enum, bounds, pattern) and a
/// checker for it. Every object closes with <c>additionalProperties: false</c>: an argument the schema does not name is
/// refused, so the golden file is the whole surface.
/// </summary>
internal static class S
{
    public static JsonObject Obj(IEnumerable<(string Name, JsonObject Schema)> props, params string[] required)
    {
        var p = new JsonObject();
        foreach (var (name, schema) in props)
            p[name] = schema;
        var o = new JsonObject { ["type"] = "object", ["properties"] = p };
        if (required.Length > 0)
            o["required"] = new JsonArray([.. required.Select(r => (JsonNode)JsonValue.Create(r))]);
        o["additionalProperties"] = false;
        return o;
    }

    public static JsonObject Empty() => Obj([]);

    public static JsonObject Str(string description, int maxLength = 256, string? pattern = null, IEnumerable<string>? values = null)
    {
        var o = new JsonObject { ["type"] = "string", ["description"] = description };
        if (values is not null)
            o["enum"] = new JsonArray([.. values.Select(v => (JsonNode)JsonValue.Create(v))]);
        else
            o["maxLength"] = maxLength;
        if (pattern is not null)
            o["pattern"] = pattern;
        return o;
    }

    public static JsonObject Int(string description, int min, int max) =>
        new() { ["type"] = "integer", ["description"] = description, ["minimum"] = min, ["maximum"] = max };

    public static JsonObject Bool(string description) => new() { ["type"] = "boolean", ["description"] = description };

    public static JsonObject Arr(string description, JsonObject items, int maxItems, int minItems = 0)
    {
        var o = new JsonObject { ["type"] = "array", ["description"] = description, ["items"] = items, ["maxItems"] = maxItems };
        if (minItems > 0)
            o["minItems"] = minItems;
        return o;
    }

    /// <summary>
    /// A schema pattern (ECMA-262, where a final <c>$</c> is the end of the input) for .NET, where <c>$</c> also
    /// matches before a trailing newline: "name\n" must not pass <c>^[a-z]+$</c>. The published schema keeps the
    /// <c>$</c> its clients understand.
    /// </summary>
    internal static string NetPattern(string pattern) =>
        pattern.EndsWith('$') && !pattern.EndsWith("\\$", StringComparison.Ordinal) ? pattern[..^1] + "\\z" : pattern;

    private static long Long(JsonNode? n) => long.Parse(n!.ToJsonString(), CultureInfo.InvariantCulture);

    /// <summary>Checks <paramref name="value"/> against <paramref name="schema"/>; returns the first problem or null.</summary>
    public static string? Check(JsonObject schema, JsonNode? value, string at = "arguments")
    {
        var type = (string?)schema["type"];
        switch (type)
        {
            case "object":
                if (value is not JsonObject o)
                    return $"{at}: an object is expected";
                var props = schema["properties"] as JsonObject ?? [];
                foreach (var req in schema["required"] as JsonArray ?? [])
                {
                    if (!o.ContainsKey((string)req!))
                        return $"{at}.{(string)req!}: required";
                }
                foreach (var (k, v) in o)
                {
                    if (props[k] is not JsonObject ps)
                        return $"{at}.{k}: unknown argument (allowed: {string.Join(", ", props.Select(p => p.Key))})";
                    if (Check(ps, v, $"{at}.{k}") is { } e)
                        return e;
                }
                return null;
            case "string":
                if (value is not JsonValue sv || sv.GetValueKind() != JsonValueKind.String)
                    return $"{at}: a string is expected";
                var s = sv.GetValue<string>();
                if (schema["enum"] is JsonArray values && !values.Any(x => (string?)x == s))
                    return $"{at}: one of {string.Join(", ", values.Select(x => (string?)x))} is expected";
                if (schema["maxLength"] is JsonNode ml && s.Length > (int)ml)
                    return $"{at}: longer than {(int)ml} characters";
                if (schema["pattern"] is JsonNode pat && !System.Text.RegularExpressions.Regex.IsMatch(s, NetPattern((string)pat!),System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(1)))
                    return $"{at}: does not match {(string?)pat}";
                return null;
            case "integer":
                if (value is not JsonValue iv || iv.GetValueKind() != JsonValueKind.Number || !long.TryParse(iv.ToJsonString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n))
                    return $"{at}: an integer is expected";
                if (n < Long(schema["minimum"]) || n > Long(schema["maximum"]))
                    return $"{at}: must be from {schema["minimum"]} to {schema["maximum"]}";
                return null;
            case "boolean":
                return value is JsonValue bv && bv.GetValueKind() is JsonValueKind.True or JsonValueKind.False ? null : $"{at}: true or false is expected";
            case "array":
                if (value is not JsonArray a)
                    return $"{at}: an array is expected";
                if (a.Count > (int)schema["maxItems"]!)
                    return $"{at}: at most {(int)schema["maxItems"]!} items";
                if (schema["minItems"] is JsonNode mi && a.Count < (int)mi)
                    return $"{at}: at least {(int)mi} items";
                for (int i = 0; i < a.Count; i++)
                {
                    if (Check((JsonObject)schema["items"]!, a[i], $"{at}[{i}]") is { } e)
                        return e;
                }
                return null;
            default:
                return $"{at}: unsupported schema";
        }
    }
}
