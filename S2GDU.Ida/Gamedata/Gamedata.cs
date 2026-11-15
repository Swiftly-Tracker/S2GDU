using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using S2GDU.Ida.Model;
using S2GDU.Ida.Storage;

namespace S2GDU.Ida.Gamedata;

public sealed record SeedEntry(string Name, string Sig, string Library, int Offset);

public sealed record ExportSummary(int Signatures, int Offsets, List<string> Conflicts);

public static class Gamedata
{
    public const string OffsetsFile = "offsets.jsonc";
    public const string SignaturesFile = "signatures.jsonc";

    public static bool IsLinuxBinary(string binaryName) =>
        binaryName.Contains(".so", StringComparison.Ordinal) || binaryName.Contains(".dylib", StringComparison.Ordinal);

    public static string LibraryName(string binaryName)
    {
        string name = Path.GetFileName(binaryName);
        int dot = name.LastIndexOf('.');
        if (dot >= 0)
        {
            name = name[..dot];
        }

        return name.Length > 3 && name.StartsWith("lib", StringComparison.Ordinal) ? name[3..] : name;
    }

    public static List<SeedEntry> ReadSeed(string directory, bool linux)
    {
        if (!Directory.Exists(directory))
        {
            throw new ArgumentException($"Seed directory '{directory}' does not exist.");
        }

        var entries = new List<SeedEntry>();
        bool found = false;
        foreach (string file in new[] { SignaturesFile, OffsetsFile })
        {
            string path = Path.Combine(directory, file);
            if (File.Exists(path))
            {
                found = true;
                ReadSeedFile(path, linux, entries);
            }
        }

        return found ? entries : throw new InvalidDataException($"Seed directory '{directory}' has no {SignaturesFile} or {OffsetsFile}.");
    }

    private static void ReadSeedFile(string path, bool linux, List<SeedEntry> entries)
    {
        var options = new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
        using var doc = JsonDocument.Parse(File.ReadAllText(path), options);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        string platform = linux ? "linux" : "windows";
        foreach (var item in doc.RootElement.EnumerateObject())
        {
            if (item.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            string sig = string.Empty;
            string library = string.Empty;
            int offset = -1;
            foreach (var field in item.Value.EnumerateObject())
            {
                if (field.Name == "lib")
                {
                    library = Str(field.Value);
                }
                else if (field.Name == platform)
                {
                    if (field.Value.ValueKind == JsonValueKind.Number)
                    {
                        offset = (int)field.Value.GetDouble();
                    }
                    else
                    {
                        sig = Str(field.Value);
                    }
                }
            }

            if (sig.Length > 0 || offset >= 0)
            {
                entries.Add(new SeedEntry(item.Name, sig, library, offset));
            }
        }
    }

    private static string Str(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() ?? string.Empty : string.Empty;

    public static Signature ParseSig(string text)
    {
        var sig = new Signature();
        foreach (string token in text.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (token[0] == '?')
            {
                sig.Bytes.Add(0);
                sig.Mask.Add(false);
            }
            else if (byte.TryParse(token.Length > 2 ? token[..2] : token, NumberStyles.HexNumber, null, out byte b))
            {
                sig.Bytes.Add(b);
                sig.Mask.Add(true);
            }
        }

        return sig;
    }

    public static ExportSummary Export(IEnumerable<ClueFile> clues, string outDir, string? layoutDir = null)
    {
        var signatures = new JsonObject();
        var offsetMap = new JsonObject();
        var conflicts = new List<string>();
        int sigs = 0;
        int offsets = 0;

        foreach (var clue in clues)
        {
            string platform = IsLinuxBinary(clue.BinaryName) ? "linux" : "windows";
            string library = LibraryName(clue.BinaryName);

            foreach (var tf in clue.Functions)
            {
                if (tf.Match.Verdict != MatchVerdict.Match)
                {
                    continue;
                }

                bool isOffset = tf.VTableOffset >= 0 || tf.FieldOffset >= 0;
                if (!isOffset && tf.ExportSig.IsEmpty)
                {
                    continue;
                }

                var target = isOffset ? offsetMap : signatures;
                if (target[tf.Name] is not JsonObject entry)
                {
                    entry = [];
                    target[tf.Name] = entry;
                    if (!isOffset)
                    {
                        entry["lib"] = library;
                    }
                }

                if (entry.ContainsKey(platform))
                {
                    conflicts.Add($"{tf.Name} ({platform} {(isOffset ? "offset" : "signature")})");
                    continue;
                }

                if (isOffset)
                {
                    entry[platform] = tf.FieldOffset >= 0 ? tf.FieldOffset : tf.VTableOffset;
                    offsets++;
                }
                else
                {
                    entry[platform] = tf.ExportSig.ToIda();
                    sigs++;
                }
            }
        }

        Directory.CreateDirectory(outDir);
        WriteLayout(Path.Combine(outDir, SignaturesFile), layoutDir == null ? null : Path.Combine(layoutDir, SignaturesFile), signatures, "lib", "windows", "linux");
        WriteLayout(Path.Combine(outDir, OffsetsFile), layoutDir == null ? null : Path.Combine(layoutDir, OffsetsFile), offsetMap, "windows", "linux");
        return new ExportSummary(sigs, offsets, conflicts);
    }

    private static readonly JsonSerializerOptions ScalarOptions = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private static void WriteLayout(string path, string? layoutPath, JsonObject data, params string[] order)
    {
        string text = layoutPath != null && File.Exists(layoutPath) ? File.ReadAllText(layoutPath) : "{\n}";
        text = text.Replace("\r\n", "\n");

        var scan = Scan(text);
        var existing = new HashSet<string>(scan.Entries.Select(e => e.Key), StringComparer.Ordinal);
        var edits = new List<(int Start, int End, string Text)>();

        foreach (var (key, start, end) in scan.Entries)
        {
            if (data[key] is not JsonObject fresh)
            {
                continue;
            }

            var merged = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
            var options = new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };
            using (var doc = JsonDocument.Parse(text[start..(end + 1)], options))
            {
                foreach (var field in doc.RootElement.EnumerateObject())
                {
                    merged[field.Name] = JsonNode.Parse(field.Value.GetRawText());
                }
            }

            foreach (var (name, value) in fresh)
            {
                merged[name] = value?.DeepClone();
            }

            edits.Add((start, end + 1, RenderEntry(merged, order)));
        }

        var added = new List<string>();
        foreach (var (key, value) in data)
        {
            if (existing.Contains(key) || value is not JsonObject fresh)
            {
                continue;
            }

            var merged = fresh.ToDictionary(kv => kv.Key, kv => kv.Value?.DeepClone(), StringComparer.Ordinal);
            added.Add($"    {JsonSerializer.Serialize(key, ScalarOptions)}: {RenderEntry(merged, order)}");
        }

        if (added.Count > 0)
        {
            string separator = text[scan.LastSignificant] is '{' or ',' ? string.Empty : ",";
            edits.Add((scan.LastSignificant + 1, scan.LastSignificant + 1, separator + "\n" + string.Join(",\n", added)));
        }

        var result = new System.Text.StringBuilder(text);
        foreach (var (start, end, replacement) in edits.OrderByDescending(e => e.Start))
        {
            result.Remove(start, end - start).Insert(start, replacement);
        }

        File.WriteAllText(path, result.ToString().TrimEnd('\n') + "\n");
    }

    private static string RenderEntry(Dictionary<string, JsonNode?> fields, string[] order)
    {
        var keys = order.Where(fields.ContainsKey).Concat(fields.Keys.Where(k => !order.Contains(k))).ToList();
        var lines = keys.Select(k => $"        {JsonSerializer.Serialize(k, ScalarOptions)}: {fields[k]?.ToJsonString(ScalarOptions) ?? "null"}");
        return "{\n" + string.Join(",\n", lines) + "\n    }";
    }

    private sealed record LayoutScan(List<(string Key, int Start, int End)> Entries, int LastSignificant);

    private static LayoutScan Scan(string t)
    {
        var entries = new List<(string, int, int)>();
        int depth = 0;
        int last = 0;
        int i = 0;
        while (i < t.Length)
        {
            int next = SkipTrivia(t, i);
            if (next != i)
            {
                i = next;
                continue;
            }

            char c = t[i];
            if (c == '"')
            {
                int close = StringEnd(t, i);
                if (depth == 1)
                {
                    int colon = SkipTrivia(t, close + 1);
                    if (colon < t.Length && t[colon] == ':')
                    {
                        int open = SkipTrivia(t, colon + 1);
                        if (open < t.Length && t[open] == '{')
                        {
                            int end = ObjectEnd(t, open);
                            entries.Add((JsonSerializer.Deserialize<string>(t[i..(close + 1)])!, open, end));
                            last = end;
                            i = end + 1;
                            continue;
                        }
                    }
                }

                last = close;
                i = close + 1;
                continue;
            }

            if (c == '{')
            {
                depth++;
            }
            else if (c == '}')
            {
                depth--;
                if (depth == 0)
                {
                    break;
                }
            }

            last = i;
            i++;
        }

        return new LayoutScan(entries, last);
    }

    private static int SkipTrivia(string t, int i)
    {
        while (i < t.Length)
        {
            if (char.IsWhiteSpace(t[i]))
            {
                i++;
            }
            else if (t[i] == '/' && i + 1 < t.Length && t[i + 1] == '/')
            {
                int nl = t.IndexOf('\n', i);
                i = nl < 0 ? t.Length : nl + 1;
            }
            else if (t[i] == '/' && i + 1 < t.Length && t[i + 1] == '*')
            {
                int close = t.IndexOf("*/", i + 2, StringComparison.Ordinal);
                i = close < 0 ? t.Length : close + 2;
            }
            else
            {
                break;
            }
        }

        return i;
    }

    private static int StringEnd(string t, int open)
    {
        int i = open + 1;
        while (i < t.Length && t[i] != '"')
        {
            i += t[i] == '\\' ? 2 : 1;
        }

        return Math.Min(i, t.Length - 1);
    }

    private static int ObjectEnd(string t, int open)
    {
        int depth = 0;
        int i = open;
        while (i < t.Length)
        {
            int next = SkipTrivia(t, i);
            if (next != i)
            {
                i = next;
                continue;
            }

            if (t[i] == '"')
            {
                i = StringEnd(t, i) + 1;
                continue;
            }

            if (t[i] == '{')
            {
                depth++;
            }
            else if (t[i] == '}' && --depth == 0)
            {
                return i;
            }

            i++;
        }

        return t.Length - 1;
    }
}
