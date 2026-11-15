using System.Text.Json.Serialization;
using S2GDU.Ida.Jobs;

namespace S2GDU.Ida.Worker;

internal enum WireKind { Ready, Job, Progress, Done, Failed, Quit }

internal sealed class WireMessage
{
    public required WireKind Kind { get; init; }

    public JobRequest? Request { get; init; }
    public JobResult? Result { get; init; }

    public string? Sdk { get; init; }

    public double Fraction { get; init; }
    public string? Stage { get; init; }
    public ulong Address { get; init; }

    public double Milliseconds { get; init; }
    public string? Error { get; init; }
}

[JsonSerializable(typeof(WireMessage))]
[JsonSerializable(typeof(JobRequest))]
[JsonSerializable(typeof(JobResult))]
internal partial class WireJsonContext : JsonSerializerContext;
