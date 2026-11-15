using System.Text;

namespace S2GDU.Ida.Model;

public enum ModulePriority : byte
{
    Signature = 0,
    UniqueStr = 1,
    ConVar = 2,
    VTable = 3,
    Library = 4,
    Relational = 5,
    DataPtr = 6,
    Proximity = 7,
    CallChain = 8,
    Xref = 9,
}

public enum MatchVerdict : byte
{
    None = 0,
    Ambiguous = 1,
    Match = 2,
}

public static class IdentityFlags
{
    public const uint HasLoop = 1 << 0;
    public const uint HasFloatOps = 1 << 1;
    public const uint HasSimd = 1 << 2;
    public const uint HasDiv = 1 << 3;
    public const uint HasMul = 1 << 4;
    public const uint HasLargeStack = 1 << 5;
    public const uint HasRepOps = 1 << 6;
    public const uint HasCmov = 1 << 7;
}

public static class Names
{
    public static string Of(ModulePriority priority) => priority switch
    {
        ModulePriority.Signature => "SIGNATURE",
        ModulePriority.UniqueStr => "UNIQUE_STR",
        ModulePriority.ConVar => "CONVAR",
        ModulePriority.VTable => "VTABLE",
        ModulePriority.Library => "LIBRARY",
        ModulePriority.Relational => "RELATIONAL",
        ModulePriority.DataPtr => "DATA_PTR",
        ModulePriority.Proximity => "PROXIMITY",
        ModulePriority.CallChain => "CALLCHAIN",
        ModulePriority.Xref => "XREF",
        _ => "UNKNOWN",
    };

    public static string Of(MatchVerdict verdict) => verdict switch
    {
        MatchVerdict.None => "NONE",
        MatchVerdict.Ambiguous => "AMBIGUOUS",
        MatchVerdict.Match => "MATCH",
        _ => "UNKNOWN",
    };
}

public sealed class Signature
{
    public List<byte> Bytes { get; } = [];
    public List<bool> Mask { get; } = [];
    public uint Offset { get; set; }

    public bool IsEmpty => Bytes.Count == 0;
    public int Length => Bytes.Count;

    public Signature Clone()
    {
        var copy = new Signature { Offset = Offset };
        copy.Bytes.AddRange(Bytes);
        copy.Mask.AddRange(Mask);
        return copy;
    }

    public string ToIda()
    {
        var sb = new StringBuilder(Bytes.Count * 3);
        for (int i = 0; i < Bytes.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(' ');
            }

            if (Mask[i])
            {
                sb.Append(Bytes[i].ToString("X2"));
            }
            else
            {
                sb.Append('?');
            }
        }

        return sb.ToString();
    }

    public string ToGamedata()
    {
        var sb = new StringBuilder(Bytes.Count * 4);
        for (int i = 0; i < Bytes.Count; i++)
        {
            sb.Append(Mask[i] ? $"\\x{Bytes[i]:X2}" : "\\x2A");
        }

        return sb.ToString();
    }

    public static Signature ParseIda(string text)
    {
        var sig = new Signature();
        foreach (string token in text.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token is "?" or "??")
            {
                sig.Bytes.Add(0);
                sig.Mask.Add(false);
            }
            else
            {
                sig.Bytes.Add(Convert.ToByte(token, 16));
                sig.Mask.Add(true);
            }
        }

        return sig;
    }
}

public sealed class Identity
{
    public string ReturnType { get; set; } = string.Empty;
    public List<string> ParamTypes { get; } = [];
    public byte ParamCount { get; set; }
    public bool HasReturn { get; set; }
    public bool HasIndirectCall { get; set; }
    public bool HasSwitch { get; set; }
    public uint StructFlags { get; set; }
}

public sealed class Reinforcement
{
    public uint Size { get; set; }
    public ushort BbCount { get; set; }
    public ushort Cyclomatic { get; set; }
    public uint CallerCount { get; set; }
    public uint CalleeCount { get; set; }
    public List<string> Strings { get; } = [];
    public List<ulong> Constants { get; } = [];
}

public sealed class Anchor
{
    public const ulong BadAddr = ulong.MaxValue;

    public ModulePriority Priority { get; set; }
    public string Name { get; set; } = string.Empty;
    public Signature Signature { get; set; } = new();
    public uint Index { get; set; }
    public uint VTableSize { get; set; }
    public uint VTableNeighborBefore { get; set; }
    public uint VTableNeighborAfter { get; set; }
    public ulong Rva { get; set; }
    public uint Fanout { get; set; }
    public ulong ResolvedEa { get; set; } = BadAddr;
    public byte ChainDepth { get; set; }
    public byte ChainDirections { get; set; }
    public byte ChainLandmarkType { get; set; }
    public uint FuncSize { get; set; }
}

public sealed class CrawlResult
{
    public Identity Identity { get; set; } = new();
    public Reinforcement Reinforcement { get; set; } = new();
    public List<Anchor> Anchors { get; } = [];
}

public readonly record struct FinderResult(ulong Candidate, ModulePriority Source, string Detail);

public sealed class MatchResult
{
    public MatchVerdict Verdict { get; set; } = MatchVerdict.None;
    public ulong MatchedEa { get; set; } = Anchor.BadAddr;
    public string Method { get; set; } = string.Empty;
    public uint Votes { get; set; }
    public uint Structural { get; set; }
    public bool IdentityPassed { get; set; }
    public float ReinforcementScore { get; set; }
}

public sealed class TrackedFunc
{
    public string Name { get; set; } = string.Empty;
    public ulong OriginalEa { get; set; } = Anchor.BadAddr;
    public Identity Identity { get; set; } = new();
    public Reinforcement Reinforcement { get; set; } = new();
    public List<Anchor> Anchors { get; set; } = [];
    public Signature ExportSig { get; set; } = new();
    public Signature TrackingSig { get; set; } = new();
    public byte PrologueLength { get; set; }
    public int SigOffset { get; set; }
    public List<ushort> MidContext { get; set; } = [];
    public string VTableClass { get; set; } = string.Empty;
    public int VTableOffset { get; set; } = -1;
    public int FieldOffset { get; set; } = -1;
    public MatchResult Match { get; set; } = new();
}
