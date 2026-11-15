using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using S2GDU.Ida.Generated;
using S2GDU.Ida.Jobs;

namespace S2GDU.Ida.Worker;

public sealed record BatchItem(JobRequest Request, bool Succeeded, JobResult? Result, TimeSpan Elapsed, string? Error);

public sealed class IdaWorkerPool(string idaPath, IdaSdkVersion sdk, int size) : IDisposable
{
    private readonly List<Worker> _workers = [];

    public Action<string> Log { get; set; } = Console.Error.WriteLine;

    public IReadOnlyList<BatchItem> RunBatch(
        IReadOnlyList<JobRequest> jobs,
        Action<JobRequest, int>? onStarted = null,
        Action<int, BatchItem>? onFinished = null,
        Action<int, double, ulong>? onProgress = null,
        Action<int, string>? onStage = null)
    {
        if (jobs.Count == 0)
        {
            return [];
        }

        int workerCount = Math.Clamp(size, 1, jobs.Count);
        var results = new BatchItem?[jobs.Count];
        var plan = Partition(jobs, workerCount);
        var threads = new List<Thread>(workerCount);

        for (int i = 0; i < workerCount; i++)
        {
            var worker = new Worker(i, idaPath, sdk, line => Log(line));
            _workers.Add(worker);
            var assigned = plan[i];

            var thread = new Thread(() =>
            {
                foreach (int index in assigned)
                {
                    onStarted?.Invoke(jobs[index], worker.Index);
                    var item = worker.Run(
                        jobs[index],
                        (fraction, address) => onProgress?.Invoke(worker.Index, fraction, address),
                        stage => onStage?.Invoke(worker.Index, stage));
                    results[index] = item;
                    onFinished?.Invoke(worker.Index, item);
                }
            })
            { IsBackground = true, Name = $"ida-worker-{i}" };

            threads.Add(thread);
        }

        foreach (var thread in threads)
        {
            thread.Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        return [.. results.Select(r => r!)];
    }

    private static List<int>[] Partition(IReadOnlyList<JobRequest> jobs, int workerCount)
    {
        var plan = new List<int>[workerCount];
        var load = new long[workerCount];
        for (int i = 0; i < workerCount; i++)
        {
            plan[i] = [];
        }

        long Size(int index) => File.Exists(jobs[index].Database) ? new FileInfo(jobs[index].Database).Length : 0;

        foreach (int index in Enumerable.Range(0, jobs.Count).OrderByDescending(Size))
        {
            int target = Array.IndexOf(load, load.Min());
            plan[target].Add(index);
            load[target] += Math.Max(Size(index), 1);
        }

        return plan;
    }

    public void Dispose()
    {
        foreach (var worker in _workers)
        {
            worker.Dispose();
        }

        _workers.Clear();
    }

    private sealed class Worker(int index, string idaPath, IdaSdkVersion sdk, Action<string> log) : IDisposable
    {
        private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

        private Process? _process;
        private bool _used;

        internal int Index => index;

        internal BatchItem Run(JobRequest job, Action<double, ulong>? onProgress, Action<string>? onStage)
        {
            var request = new JobRequest
            {
                Command = job.Command,
                Database = Path.GetFullPath(job.Database),
                Seed = job.Seed == null ? null : Path.GetFullPath(job.Seed),
                Clue = job.Clue == null ? null : Path.GetFullPath(job.Clue),
                Output = job.Output == null ? null : Path.GetFullPath(job.Output),
                Targets = job.Targets,
            };

            if (_used)
            {
                Dispose();
            }

            _used = true;

            if (_process is not { HasExited: false } && !Start())
            {
                return Failed(job, $"Worker {index} could not be started.");
            }

            var process = _process!;

            try
            {
                process.StandardInput.WriteLine(WorkerProtocol.Write(new WireMessage { Kind = WireKind.Job, Request = request }));
                process.StandardInput.Flush();

                while (process.StandardOutput.ReadLine() is { } line)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    var message = WorkerProtocol.Read(line);
                    if (message == null)
                    {
                        log($"[worker {index}] {line}");
                        continue;
                    }

                    switch (message.Kind)
                    {
                        case WireKind.Progress when message.Stage != null:
                            onStage?.Invoke(message.Stage);
                            break;
                        case WireKind.Progress:
                            onProgress?.Invoke(message.Fraction, message.Address);
                            break;
                        case WireKind.Done:
                            return new BatchItem(job, true, message.Result, TimeSpan.FromMilliseconds(message.Milliseconds), null);
                        case WireKind.Failed:
                            return Failed(job, message.Error ?? "The worker did not say why.");
                    }
                }

                return Failed(job, $"Worker {index} exited during analysis.");
            }
            catch (IOException ex)
            {
                return Failed(job, $"Lost contact with worker {index}: {ex.Message}");
            }
        }

        private bool Start()
        {
            Kill();

            string? host = Environment.ProcessPath;
            if (string.IsNullOrEmpty(host))
            {
                return false;
            }

            var info = new ProcessStartInfo(host)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardInputEncoding = Utf8NoBom,
                StandardOutputEncoding = Utf8NoBom,
                StandardErrorEncoding = Utf8NoBom,
            };

            string hostName = Path.GetFileNameWithoutExtension(host);
            if (hostName.Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                string? entryDll = Environment.GetCommandLineArgs().FirstOrDefault();

                if (string.IsNullOrEmpty(entryDll) || !entryDll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                info.ArgumentList.Add(entryDll);
            }

            info.ArgumentList.Add("--ida-worker");
            info.ArgumentList.Add("--ida-path");
            info.ArgumentList.Add(idaPath);

            if (sdk != IdaSdkVersion.Auto)
            {
                info.ArgumentList.Add("--ida-sdk");
                info.ArgumentList.Add(sdk.ToString());
            }

            try
            {
                _process = Process.Start(info);
            }
            catch (Exception)
            {
                return false;
            }

            if (_process == null)
            {
                return false;
            }

            _process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    log($"[worker {index}] {e.Data}");
                }
            };

            _process.BeginErrorReadLine();

            string? readyLine = _process.StandardOutput.ReadLine();
            var ready = readyLine != null ? WorkerProtocol.Read(readyLine) : null;

            if (ready?.Kind != WireKind.Ready)
            {
                Kill();
                return false;
            }

            return true;
        }

        private static BatchItem Failed(JobRequest job, string error) => new(job, false, null, TimeSpan.Zero, error);

        private void Kill()
        {
            var process = _process;
            _process = null;

            if (process == null)
            {
                return;
            }

            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                process.Dispose();
            }
        }

        public void Dispose()
        {
            var process = _process;

            if (process is { HasExited: false })
            {
                try
                {
                    process.StandardInput.WriteLine(WorkerProtocol.Write(new WireMessage { Kind = WireKind.Quit }));
                    process.StandardInput.Flush();
                    process.WaitForExit(5000);
                }
                catch (Exception)
                {
                }
            }

            Kill();
        }
    }
}
