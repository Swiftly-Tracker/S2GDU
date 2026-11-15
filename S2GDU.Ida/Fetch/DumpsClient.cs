using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using SharpCompress.Archives;
using SharpCompress.Common;

namespace S2GDU.Ida.Fetch;

public sealed record FetchedDatabase(string Archive, string Path, bool Cached);

public sealed record FetchResult(string Tag, string Directory, List<FetchedDatabase> Databases);

public sealed class DumpsClient : IDisposable
{
    public const string DefaultRepo = "Swiftly-Tracker/CS2-IDA-Dumps";
    private const string ArchiveSuffix = ".i64.7z";
    private const string ProvenanceAsset = "provenance.json";

    private readonly HttpClient _http;
    private readonly string _repo;

    public DumpsClient(string repo = DefaultRepo, string? token = null)
    {
        _repo = repo;
        _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("S2GDU", "1.0"));
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        if (!string.IsNullOrEmpty(token))
        {
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
    }

    public void Dispose() => _http.Dispose();

    public async Task<FetchResult> FetchAsync(string tag, string cacheRoot, Regex? filter, int parallelism, Action<string> log, CancellationToken ct = default)
    {
        string url = tag is "" or "latest"
            ? $"https://api.github.com/repos/{_repo}/releases/latest"
            : $"https://api.github.com/repos/{_repo}/releases/tags/{Uri.EscapeDataString(tag)}";

        using var release = JsonDocument.Parse(await GetStringAsync(url, ct));
        string resolved = release.RootElement.GetProperty("tag_name").GetString()
                          ?? throw new InvalidDataException("Release has no tag_name.");
        if (resolved.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || resolved is "." or "..")
        {
            throw new InvalidDataException($"Release tag '{resolved}' is not a safe directory name.");
        }

        var assets = new Dictionary<string, (string Url, string? Digest, long Size)>(StringComparer.Ordinal);
        foreach (var a in release.RootElement.GetProperty("assets").EnumerateArray())
        {
            string name = a.GetProperty("name").GetString() ?? string.Empty;
            string? digest = a.TryGetProperty("digest", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() : null;
            assets[name] = (a.GetProperty("browser_download_url").GetString() ?? string.Empty, digest, a.GetProperty("size").GetInt64());
        }

        var provenance = assets.TryGetValue(ProvenanceAsset, out var prov)
            ? ParseProvenance(await GetStringAsync(prov.Url, ct))
            : new Dictionary<string, ProvenanceArtifact>(StringComparer.Ordinal);
        if (provenance.Count == 0)
        {
            log("warning: release has no provenance.json; falling back to GitHub asset digests");
        }

        string dir = Path.GetFullPath(Path.Combine(cacheRoot, resolved));
        Directory.CreateDirectory(dir);

        var wanted = assets.Keys
            .Where(n => n.EndsWith(ArchiveSuffix, StringComparison.Ordinal) && Path.GetFileName(n) == n)
            .Where(n => filter == null || filter.IsMatch(n[..^ArchiveSuffix.Length]))
            .OrderByDescending(n => assets[n].Size)
            .ToList();

        var results = new FetchedDatabase[wanted.Count];
        await Parallel.ForEachAsync(Enumerable.Range(0, wanted.Count), new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, parallelism), CancellationToken = ct }, async (i, token) =>
        {
            string name = wanted[i];
            provenance.TryGetValue(name, out var art);
            string archiveHash = art?.ArchiveSha256 ?? StripDigest(assets[name].Digest)
                                 ?? throw new InvalidDataException($"No SHA-256 is published for '{name}'.");
            results[i] = await FetchOneAsync(name, assets[name].Url, archiveHash, art, dir, log, token);
        });

        return new FetchResult(resolved, dir, [.. results]);
    }

    private async Task<FetchedDatabase> FetchOneAsync(string name, string url, string archiveHash, ProvenanceArtifact? art, string dir, Action<string> log, CancellationToken ct)
    {
        string target = Path.Combine(dir, name[..^3]);
        if (File.Exists(target) && (art == null || new FileInfo(target).Length == art.Bytes))
        {
            log($"{name}: cached");
            return new FetchedDatabase(name, target, true);
        }

        string work = Path.Combine(dir, ".partial", name);
        Directory.CreateDirectory(work);
        try
        {
            string archivePath = Path.Combine(work, name);
            log($"{name}: downloading");
            string got = await DownloadAsync(url, archivePath, ct);
            if (!string.Equals(got, archiveHash, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"{name}: SHA-256 mismatch (expected {archiveHash}, got {got}).");
            }

            log($"{name}: extracting");
            string outDir = Path.Combine(work, "out");
            Directory.CreateDirectory(outDir);
            using (var archive = ArchiveFactory.OpenArchive(archivePath))
            {
                archive.WriteToDirectory(outDir, new ExtractionOptions { ExtractFullPath = false, Overwrite = true });
            }

            string expected = Path.GetFileName(target);
            string extracted = Directory.EnumerateFiles(outDir).FirstOrDefault(f => Path.GetFileName(f) == expected)
                               ?? throw new InvalidDataException($"{name}: archive does not contain '{expected}'.");

            if (art?.Sha256 is { Length: > 0 } dbHash)
            {
                string actual = await HashFileAsync(extracted, ct);
                if (!string.Equals(actual, dbHash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException($"{name}: extracted database SHA-256 mismatch (expected {dbHash}, got {actual}).");
                }
            }

            File.Move(extracted, target, overwrite: true);
            log($"{name}: ok");
            return new FetchedDatabase(name, target, false);
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    private async Task<string> GetStringAsync(string url, CancellationToken ct)
    {
        using var response = await _http.GetAsync(url, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"GET {url} returned {(int)response.StatusCode} {response.ReasonPhrase}.");
        }

        return await response.Content.ReadAsStringAsync(ct);
    }

    private async Task<string> DownloadAsync(string url, string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"GET {url} returned {(int)response.StatusCode} {response.ReasonPhrase}.");
        }

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var source = await response.Content.ReadAsStreamAsync(ct);
        await using var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, useAsync: true);
        var buffer = new byte[1 << 20];
        int read;
        while ((read = await source.ReadAsync(buffer, ct)) > 0)
        {
            sha.AppendData(buffer, 0, read);
            await file.WriteAsync(buffer.AsMemory(0, read), ct);
        }

        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken ct)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, useAsync: true);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, ct));
    }

    private static string? StripDigest(string? digest) =>
        digest != null && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? digest[7..] : null;

    private sealed record ProvenanceArtifact(string? ArchiveSha256, string? Sha256, long Bytes);

    private static Dictionary<string, ProvenanceArtifact> ParseProvenance(string json)
    {
        var map = new Dictionary<string, ProvenanceArtifact>(StringComparer.Ordinal);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("platforms", out var platforms) || platforms.ValueKind != JsonValueKind.Array)
        {
            return map;
        }

        foreach (var p in platforms.EnumerateArray())
        {
            if (!p.TryGetProperty("artifacts", out var arts) || arts.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var a in arts.EnumerateArray())
            {
                string? archive = Text(a, "archive");
                if (archive == null)
                {
                    continue;
                }

                long bytes = a.TryGetProperty("bytes", out var b) && b.ValueKind == JsonValueKind.Number ? b.GetInt64() : -1;
                map[archive] = new ProvenanceArtifact(Text(a, "archiveSha256"), Text(a, "sha256"), bytes);
            }
        }

        return map;
    }

    private static string? Text(JsonElement e, string key) =>
        e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
