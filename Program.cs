using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using S2GDU.Ida.Fetch;
using S2GDU.Ida.Gamedata;
using S2GDU.Ida.Generated;
using S2GDU.Ida.Jobs;
using S2GDU.Ida.Model;
using S2GDU.Ida.Storage;
using S2GDU.Ida.Worker;
using Spectre.Console;
using GD = S2GDU.Ida.Gamedata.Gamedata;

namespace S2GDU;

internal sealed class CliOptions
{
    public string? Command { get; private set; }
    public List<string> Positional { get; } = [];
    public string? IdaPath { get; private set; } = Environment.GetEnvironmentVariable("IDA_PATH");
    public IdaSdkVersion SdkVersion { get; private set; } = IdaSdkVersion.Auto;
    public int Cores { get; private set; } = Environment.ProcessorCount;
    public string? Input { get; private set; }
    public string? Seed { get; private set; }
    public string? Layout { get; private set; }
    public string? Clues { get; private set; }
    public string? Clue { get; private set; }
    public string? Out { get; private set; }
    public string Tag { get; private set; } = "latest";
    public string Cache { get; private set; } = "cache";
    public string Repo { get; private set; } = DumpsClient.DefaultRepo;
    public bool IsWorker { get; private set; }
    public bool ShowHelp { get; private set; }
    public string? ParseError { get; private set; }

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            bool hasValue = i + 1 < args.Length;
            switch (a)
            {
                case "--ida-worker": o.IsWorker = true; break;
                case "-h" or "--help": o.ShowHelp = true; break;
                case "--ida-path" when hasValue: o.IdaPath = args[++i]; break;
                case "--ida-sdk" when hasValue: o.SdkVersion = ParseSdkVersion(args[++i]); break;
                case "--cores" when hasValue:
                    if (!int.TryParse(args[++i], out int cores) || cores < 1)
                    {
                        o.ParseError = "--cores must be a positive integer.";
                    }
                    else
                    {
                        o.Cores = cores;
                    }

                    break;
                case "--input" when hasValue: o.Input = args[++i]; break;
                case "--seed" when hasValue: o.Seed = args[++i]; break;
                case "--layout" when hasValue: o.Layout = args[++i]; break;
                case "--clues" when hasValue: o.Clues = args[++i]; break;
                case "--clue" when hasValue: o.Clue = args[++i]; break;
                case "--out" when hasValue: o.Out = args[++i]; break;
                case "--tag" when hasValue: o.Tag = args[++i]; break;
                case "--cache" when hasValue: o.Cache = args[++i]; break;
                case "--repo" when hasValue: o.Repo = args[++i]; break;
                case "--ida-path" or "--ida-sdk" or "--cores" or "--input" or "--seed" or "--layout" or "--clues" or "--clue" or "--out"
                    or "--tag" or "--cache" or "--repo":
                    o.ParseError = $"{a} requires a value.";
                    break;
                default:
                    if (a.StartsWith("--", StringComparison.Ordinal))
                    {
                        o.ParseError = $"Unknown option '{a}'.";
                    }
                    else if (o.Command == null)
                    {
                        o.Command = a.ToLowerInvariant();
                    }
                    else
                    {
                        o.Positional.Add(a);
                    }

                    break;
            }
        }

        return o;
    }

    private static IdaSdkVersion ParseSdkVersion(string value)
    {
        string normalized = value.Trim().Replace(".", "", StringComparison.Ordinal).ToUpperInvariant();
        if (normalized is "AUTO" or "")
        {
            return IdaSdkVersion.Auto;
        }

        if (!normalized.StartsWith('V'))
        {
            normalized = "V" + normalized;
        }

        return Enum.TryParse(normalized, out IdaSdkVersion sdk) ? sdk : IdaSdkVersion.Auto;
    }
}

public static class Program
{
    private const string DatabaseExtension = ".i64";
    private const string ReportExtension = ".report.json";

    public static int Main(string[] args)
    {
        var o = CliOptions.Parse(args);
        if (o.IsWorker)
        {
            if (string.IsNullOrWhiteSpace(o.IdaPath))
            {
                Console.Error.WriteLine("--ida-worker requires --ida-path.");
                return 1;
            }

            int workerCode = IdaWorkerProcess.Run(o.IdaPath, o.SdkVersion);
            IdaWorkerProcess.ExitNow(workerCode);
            return workerCode;
        }

        if (o.ShowHelp || o.Command == null)
        {
            PrintUsage();
            return o.ShowHelp ? 0 : 1;
        }

        if (o.ParseError != null)
        {
            Console.Error.WriteLine(o.ParseError);
            return 1;
        }

        try
        {
            return o.Command switch
            {
                "fetch" => Fetch(o),
                "import" => Import(o),
                "backtrack" => Backtrack(o),
                "track" => Track(o),
                "gensig" => Gensig(o),
                "export" => Export(o),
                "list" => List(o),
                _ => Fail($"Unknown command '{o.Command}'. Run with --help."),
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException
                                   or JsonException or HttpRequestException or RegexParseException or Google.Protobuf.InvalidProtocolBufferException)
        {
            return Fail(ex.Message);
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 1;
    }

    private static string Require(string? value, string option) =>
        value ?? throw new ArgumentException($"{option} is required.");

    private static Regex? Filter(CliOptions o) =>
        o.Positional.Count == 0 ? null : new Regex(string.Join('|', o.Positional.Select(p => $"(?:{p})")));

    private static string BinaryKey(string databasePath) =>
        Path.GetFileName(databasePath)[..^DatabaseExtension.Length];

    private static int Fetch(CliOptions o)
    {
        using var client = new DumpsClient(o.Repo, Environment.GetEnvironmentVariable("GITHUB_TOKEN"));
        var result = client.FetchAsync(o.Tag, o.Cache, Filter(o), o.Cores, Console.Error.WriteLine).GetAwaiter().GetResult();
        Console.Error.WriteLine($"{result.Databases.Count} databases in {result.Directory} ({result.Databases.Count(d => !d.Cached)} downloaded).");
        Console.WriteLine($"tag={result.Tag}");
        return 0;
    }

    private static List<string> Databases(CliOptions o)
    {
        string input = Require(o.Input, "--input");
        if (!Directory.Exists(input))
        {
            throw new ArgumentException($"--input directory '{input}' does not exist.");
        }

        var filter = Filter(o);
        return [.. Directory.EnumerateFiles(input, "*" + DatabaseExtension)
            .Where(p => filter == null || filter.IsMatch(BinaryKey(p)))
            .OrderByDescending(p => new FileInfo(p).Length)];
    }

    private static int Import(CliOptions o)
    {
        string seed = Path.GetFullPath(Require(o.Seed, "--seed"));
        if (!Directory.Exists(seed))
        {
            return Fail($"Seed directory '{seed}' does not exist.");
        }

        string outDir = Path.GetFullPath(Require(o.Out, "--out"));
        var jobs = Databases(o).Select(db => new JobRequest
        {
            Command = JobCommand.Import,
            Database = db,
            Seed = seed,
            Output = Path.Combine(outDir, BinaryKey(db) + ClueFileStore.Extension),
        }).ToList();

        return RunBatch(o, jobs, outDir);
    }

    private static int Backtrack(CliOptions o)
    {
        string clues = Path.GetFullPath(Require(o.Clues, "--clues"));
        string outDir = Path.GetFullPath(Require(o.Out, "--out"));
        var jobs = new List<JobRequest>();
        foreach (string db in Databases(o))
        {
            string clue = Path.Combine(clues, BinaryKey(db) + ClueFileStore.Extension);
            if (!File.Exists(clue))
            {
                Console.Error.WriteLine($"{BinaryKey(db)}: no previous clue file, skipped.");
                continue;
            }

            jobs.Add(new JobRequest
            {
                Command = JobCommand.Backtrack,
                Database = db,
                Clue = clue,
                Output = Path.Combine(outDir, BinaryKey(db) + ClueFileStore.Extension),
            });
        }

        return RunBatch(o, jobs, outDir);
    }

    private static int Track(CliOptions o)
    {
        string db = Require(o.Input, "--input");
        if (o.Positional.Count == 0)
        {
            return Fail("track requires at least one target (function name or 0x address).");
        }

        string clue = o.Clue ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(db))!, BinaryKey(db) + ClueFileStore.Extension);
        var job = new JobRequest { Command = JobCommand.Track, Database = db, Clue = clue, Output = o.Out ?? clue, Targets = o.Positional };
        return RunBatch(o, [job], null);
    }

    private static int Gensig(CliOptions o)
    {
        string db = Require(o.Input, "--input");
        if (o.Positional.Count == 0)
        {
            return Fail("gensig requires at least one target (function name or 0x address).");
        }

        return RunBatch(o, [new JobRequest { Command = JobCommand.Gensig, Database = db, Targets = o.Positional }], null);
    }

    private static int RunBatch(CliOptions o, List<JobRequest> jobs, string? reportDir)
    {
        if (string.IsNullOrWhiteSpace(o.IdaPath))
        {
            return Fail("No IDA installation given. Pass --ida-path <dir> or set the IDA_PATH environment variable.");
        }

        if (jobs.Count == 0)
        {
            return Fail("No databases to process.");
        }

        Console.Error.WriteLine($"{o.Command}: {jobs.Count} database(s), {Math.Min(o.Cores, jobs.Count)} worker(s), SDK {o.SdkVersion}.");
        using var pool = new IdaWorkerPool(o.IdaPath, o.SdkVersion, o.Cores);
        var results = pool.RunBatch(
            jobs,
            onStarted: (job, worker) => Console.Error.WriteLine($"[worker {worker}] {Path.GetFileName(job.Database)}: started"),
            onFinished: (_, item) => Console.Error.WriteLine(item.Succeeded
                ? $"[done]   {Path.GetFileName(item.Request.Database)} ({item.Elapsed.TotalSeconds:F1}s)"
                : $"[FAILED] {Path.GetFileName(item.Request.Database)}: {item.Error}"),
            onStage: (worker, stage) => Console.Error.WriteLine($"[worker {worker}] {stage}"));

        var table = new Table().Border(TableBorder.Rounded);
        foreach (string column in new[] { "Database", "Status", "Total", "Matched", "Ambiguous", "None", "Survived", "Rescued", "Time" })
        {
            table.AddColumn(column);
        }

        foreach (var item in results)
        {
            var r = item.Result;
            if (item.Succeeded && r != null)
            {
                foreach (string line in r.Lines)
                {
                    Console.WriteLine(line);
                }

                if (reportDir != null)
                {
                    WriteReport(Path.Combine(reportDir, BinaryKey(item.Request.Database) + ReportExtension), r);
                }
            }

            table.AddRow(
                Markup.Escape(Path.GetFileName(item.Request.Database)),
                item.Succeeded ? "[green]ok[/]" : "[red]failed[/]",
                $"{r?.Total ?? 0}", $"{r?.Matched ?? 0}", $"{r?.Ambiguous ?? 0}", $"{r?.None ?? 0}",
                $"{r?.Survived ?? 0}", $"{r?.Rescued ?? 0}", $"{item.Elapsed.TotalSeconds:F1}s");
        }

        var console = AnsiConsole.Create(new AnsiConsoleSettings { Out = new AnsiConsoleOutput(Console.Error) });
        console.Write(table);

        int failed = results.Count(r => !r.Succeeded);
        Console.Error.WriteLine($"{results.Count - failed}/{results.Count} succeeded.");
        return failed == 0 ? 0 : 1;
    }

    private static void WriteReport(string path, JobResult r)
    {
        var report = new JsonObject
        {
            ["total"] = r.Total,
            ["matched"] = r.Matched,
            ["ambiguous"] = r.Ambiguous,
            ["none"] = r.None,
            ["survived"] = r.Survived,
            ["rescued"] = r.Rescued,
        };

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, report.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
    }

    private static List<string> ClueFiles(string path, Regex? filter)
    {
        if (File.Exists(path))
        {
            return [path];
        }

        if (!Directory.Exists(path))
        {
            throw new ArgumentException($"'{path}' is neither a clue file nor a directory.");
        }

        return [.. Directory.EnumerateFiles(path, "*" + ClueFileStore.Extension)
            .Where(p => filter == null || filter.IsMatch(Path.GetFileName(p)[..^ClueFileStore.Extension.Length]))
            .Order(StringComparer.Ordinal)];
    }

    private static List<ClueFile> ReadClues(List<string> files)
    {
        var clues = new ClueFile[files.Count];
        Parallel.For(0, files.Count, i => clues[i] = ClueFileStore.Read(files[i]));
        return [.. clues];
    }

    private static int Export(CliOptions o)
    {
        var files = ClueFiles(Require(o.Clues, "--clues"), Filter(o));
        if (files.Count == 0)
        {
            return Fail("No clue files found.");
        }

        string outPath = Require(o.Out, "--out");
        var summary = GD.Export(ReadClues(files), outPath, o.Layout == null ? null : Path.GetFullPath(o.Layout));
        foreach (string conflict in summary.Conflicts)
        {
            Console.Error.WriteLine($"conflict: {conflict}, kept first");
        }

        Console.Error.WriteLine($"{outPath}: {summary.Signatures} signatures, {summary.Offsets} offsets from {files.Count} clue file(s).");
        return 0;
    }

    private static int List(CliOptions o)
    {
        var files = ClueFiles(Require(o.Clues ?? o.Clue, "--clues"), Filter(o));
        foreach (var clue in ReadClues(files))
        {
            var table = new Table().Border(TableBorder.Rounded).Title(Markup.Escape(clue.BinaryName));
            foreach (string column in new[] { "Name", "Verdict", "Address", "Method", "Export" })
            {
                table.AddColumn(column);
            }

            foreach (var tf in clue.Functions.OrderBy(f => f.Name, StringComparer.Ordinal))
            {
                string verdict = tf.Match.Verdict switch
                {
                    MatchVerdict.Match => "[green]MATCH[/]",
                    MatchVerdict.Ambiguous => "[yellow]AMBIGUOUS[/]",
                    _ => "[red]NONE[/]",
                };
                ulong ea = tf.Match.MatchedEa == Anchor.BadAddr || tf.Match.MatchedEa == 0 ? tf.OriginalEa : tf.Match.MatchedEa;
                string export = tf.FieldOffset >= 0 ? $"+{tf.FieldOffset}" : tf.VTableOffset >= 0 ? $"{tf.VTableClass}[{tf.VTableOffset}]" : tf.ExportSig.ToIda();
                table.AddRow(Markup.Escape(tf.Name), verdict, $"0x{ea:X}", Markup.Escape(tf.Match.Method), Markup.Escape(export));
            }

            AnsiConsole.Write(table);
        }

        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            S2GDU - headless (idalib) CS2 gamedata tracker.

            Usage:
              s2gdu fetch     [--tag <tag|latest>] [--cache <dir>] [--repo <owner/name>] [regex]
              s2gdu import    --input <dir> --seed <dir> --out <dir> [regex]
              s2gdu backtrack --input <dir> --clues <dir> --out <dir> [regex]
              s2gdu track     --input <db.i64> [--clue <file.gdu.pb>] [--out <file.gdu.pb>] <name|0xEA> ...
              s2gdu gensig    --input <db.i64> <name|0xEA> ...
              s2gdu export    --clues <dir|file> --out <dir> [--layout <dir>] [regex]
              s2gdu list      --clues <dir|file> [regex]

            Common options:
              --ida-path <dir>   IDA installation with idalib. Falls back to IDA_PATH.
              --ida-sdk <ver>    Bindings to use: auto (default), 9.2, 9.3, 9.4.
              --cores <n>        Concurrent IDA worker processes (and fetch downloads). Default: all logical processors.
              -h, --help         Show this help.

            [regex] filters binaries by file name without extension, e.g. "server|engine2".
            fetch prints the resolved tag as its last stdout line: tag=<tag>. GITHUB_TOKEN is used when set.
            import/backtrack write <binary>.gdu.pb and <binary>.report.json into --out.
            --seed takes a SwiftlyS2 gamedata directory holding signatures.jsonc and offsets.jsonc.
            export writes signatures.jsonc and offsets.jsonc into the --out directory.
            """);
    }
}
