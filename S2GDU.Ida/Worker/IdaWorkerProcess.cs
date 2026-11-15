using System.Diagnostics;
using System.Runtime.InteropServices;
using S2GDU.Ida.Generated;
using S2GDU.Ida.Jobs;

namespace S2GDU.Ida.Worker;

public static partial class IdaWorkerProcess
{
    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(nint process, uint exitCode);

    [LibraryImport("libc", EntryPoint = "_exit")]
    private static partial void LibcExit(int code);

    public static void ExitNow(int code)
    {
        Console.Out.Flush();
        Console.Error.Flush();

        if (OperatingSystem.IsWindows())
        {
            TerminateProcess(GetCurrentProcess(), (uint)code);
        }
        else
        {
            LibcExit(code);
        }
    }

    public static int Run(string idaPath, IdaSdkVersion sdk)
    {
        if (!IdaKernel.TryInitialize(idaPath, sdk, out string? error))
        {
            Console.Error.WriteLine(error);
            return 1;
        }

        Send(new WireMessage { Kind = WireKind.Ready, Sdk = IdaKernel.SdkVersion.ToString() });

        string? line;
        while ((line = Console.In.ReadLine()) != null)
        {
            var message = WorkerProtocol.Read(line);
            if (message == null)
            {
                continue;
            }

            if (message.Kind == WireKind.Quit)
            {
                break;
            }

            if (message.Kind != WireKind.Job || message.Request == null)
            {
                continue;
            }

            RunJob(message.Request);
        }

        return 0;
    }

    private static void RunJob(JobRequest request)
    {
        if (!File.Exists(request.Database))
        {
            Send(new WireMessage { Kind = WireKind.Failed, Error = $"No such file: '{request.Database}'." });
            return;
        }

        var clock = Stopwatch.StartNew();

        try
        {
            var result = IdaKernel.Session(
                request.Database,
                save: false,
                () => JobRunner.Run(request, stage => Send(new WireMessage { Kind = WireKind.Progress, Stage = stage })),
                (fraction, address) => Send(new WireMessage { Kind = WireKind.Progress, Fraction = fraction, Address = address }));

            Send(new WireMessage { Kind = WireKind.Done, Result = result, Milliseconds = clock.Elapsed.TotalMilliseconds });
        }
        catch (Exception ex)
        {
            Send(new WireMessage { Kind = WireKind.Failed, Error = ex.Message });
        }
    }

    private static readonly Lock SendLock = new();

    private static void Send(WireMessage message)
    {
        lock (SendLock)
        {
            Console.Out.WriteLine(WorkerProtocol.Write(message));
            Console.Out.Flush();
        }
    }
}
