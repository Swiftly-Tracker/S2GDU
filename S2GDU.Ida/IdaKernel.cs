using System.Diagnostics;
using S2GDU.Ida.Generated;

namespace S2GDU.Ida;

public static unsafe class IdaKernel
{
    private static readonly TimeSpan ReportInterval = TimeSpan.FromMilliseconds(60);

    private const int OpenAttempts = 4;
    private static readonly TimeSpan OpenRetryDelay = TimeSpan.FromSeconds(2);

    private static bool _initialized;
    private static int _ownerThread;

    public static bool IsInitialized => _initialized;

    public static IdaSdkVersion SdkVersion { get; private set; }

    public static bool TryInitialize(string idaPath, IdaSdkVersion requested, out string? error)
    {
        error = null;

        if (_initialized)
        {
            return true;
        }

        if (!Directory.Exists(idaPath))
        {
            error = $"'{idaPath}' does not exist. Point --ida-path at an IDA installation.";
            return false;
        }

        string kernelFile = IdaPlatform.LibraryFileName("ida");
        string idalibFile = IdaPlatform.LibraryFileName("idalib");

        if (!File.Exists(Path.Combine(idaPath, kernelFile)) || !File.Exists(Path.Combine(idaPath, idalibFile)))
        {
            error = $"'{kernelFile}' and '{idalibFile}' were not both found in '{idaPath}'.";
            return false;
        }

        foreach (string required in new[] { "cfg", "procs" })
        {
            if (!Directory.Exists(Path.Combine(idaPath, required)))
            {
                error = $"'{idaPath}' has the IDA libraries but no '{required}' directory, so it is not a complete IDA installation.";
                return false;
            }
        }

        IdaPlatform.PreloadSiblingLibraries(idaPath);
        IdaResolver.SetRoot(idaPath);

        nint idaHandle = IdaResolver.Load("ida");
        nint idalibHandle = IdaResolver.Load("idalib");

        if (!IdaBootstrap.TryInitLibrary(idalibHandle, out int status))
        {
            error = $"'{idalibFile}' does not export init_library(); this is not an idalib build.";
            return false;
        }

        if (status != 0)
        {
            error = $"init_library() failed with status {status}. '{idaPath}' must have a valid licence.";
            return false;
        }

        if (!TrySelectVersion(idalibHandle, requested, out var selected, out error))
        {
            return false;
        }

        IdaNative.BindAll(idaHandle, idalibHandle, selected);
        IdaNative.enable_console_messages(0);

        SdkVersion = selected;
        _ownerThread = Environment.CurrentManagedThreadId;
        _initialized = true;
        return true;
    }

    private static bool TrySelectVersion(nint idalib, IdaSdkVersion requested, out IdaSdkVersion selected, out string? error)
    {
        error = null;

        if (requested != IdaSdkVersion.Auto)
        {
            selected = requested;

            if (!IdaNative.GeneratedVersions.Contains(requested))
            {
                error = $"--ida-sdk {requested} was requested, but this build only has bindings for {Describe()}.";
                return false;
            }

            return true;
        }

        selected = IdaSdkVersion.Auto;

        if (!IdaBootstrap.TryProbeVersion(idalib, out var version))
        {
            error = "The installed idalib does not report a version through get_library_version().";
            return false;
        }

        selected = IdaBootstrap.ToSdkVersion(version);

        if (selected == IdaSdkVersion.Auto || !IdaNative.GeneratedVersions.Contains(selected))
        {
            error = $"IDA {version.Major}.{version.Minor} is installed, but this build only has bindings for {Describe()}. " +
                    "Vendor that SDK under thirdparty/ida-sdk and re-run S2GDU.Ida.Codegen, or pass --ida-sdk explicitly.";
            return false;
        }

        return true;
    }

    private static string Describe() => string.Join(", ", IdaNative.GeneratedVersions.Select(v => v.ToString()));

    public static T Session<T>(string path, bool save, Func<T> body, Action<double, ulong>? onProgress = null)
    {
        AssertOwner();

        string full = Path.GetFullPath(path);
        byte* native = Utf8.Allocate(full);

        try
        {
            int status = IdaNative.open_database(native, 0, null);
            for (int attempt = 1; status != 0 && attempt < OpenAttempts; attempt++)
            {
                Thread.Sleep(OpenRetryDelay * attempt);
                status = IdaNative.open_database(native, 0, null);
            }

            if (status != 0)
            {
                throw new InvalidOperationException($"open_database() failed with status {status} for '{full}'.");
            }
        }
        finally
        {
            Utf8.Free(native);
        }

        bool completed = false;
        try
        {
            DriveAnalysis(onProgress);
            IdaNative.build_strlist();
            T result = body();
            completed = true;
            return result;
        }
        finally
        {
            IdaNative.close_database(save && completed ? (byte)1 : (byte)0);
        }
    }

    private static void DriveAnalysis(Action<double, ulong>? onProgress)
    {
        if (onProgress == null)
        {
            IdaNative.auto_wait();
            return;
        }

        var (start, end) = GetAddressSpan();
        ulong span = end > start ? end - start : 0;

        var clock = Stopwatch.StartNew();
        TimeSpan next = TimeSpan.Zero;
        double reported = 0.0;

        onProgress(0.0, start);

        while (IdaNative.auto_make_step(start, end) != 0)
        {
            if (clock.Elapsed < next || span == 0)
            {
                continue;
            }

            next = clock.Elapsed + ReportInterval;

            AutoDisplay display;
            if (IdaNative.get_auto_display(&display) == 0)
            {
                continue;
            }

            ulong ea = display.Ea;
            if (ea < start || ea > end)
            {
                continue;
            }

            double fraction = (double)(ea - start) / span;
            if (fraction <= reported)
            {
                continue;
            }

            reported = fraction;
            onProgress(fraction, ea);
        }

        IdaNative.auto_wait();
        onProgress(1.0, end);
    }

    private static (ulong Start, ulong End) GetAddressSpan()
    {
        int qty = IdaNative.get_segm_qty();
        if (qty == 0)
        {
            return (0, 0);
        }

        void* first = IdaNative.getnseg(0);
        void* last = IdaNative.getnseg(qty - 1);

        if (first == null || last == null)
        {
            return (0, 0);
        }

        return (*(ulong*)first, *((ulong*)last + 1));
    }

    internal static void AssertOwner()
    {
        if (!_initialized)
        {
            throw new InvalidOperationException("The IDA kernel has not been initialized.");
        }

        if (Environment.CurrentManagedThreadId != _ownerThread)
        {
            throw new InvalidOperationException("idalib is single-threaded and must be called from the thread that initialized it.");
        }
    }
}
