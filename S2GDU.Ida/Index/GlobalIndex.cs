using System.Buffers.Binary;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Index;

public readonly record struct InsnRecord(uint Delta, ushort Itype, byte Size, byte ImmOffset);

public readonly record struct FieldAccess(uint Delta, int Disp);

public readonly record struct VTableRef(string VTable, uint Slot);

public readonly record struct DataFuncPtr(ulong Pointer, ulong Target);

public sealed class FunctionInfo
{
    public ulong Start { get; init; }
    public ulong End { get; init; }
    public string Name { get; init; } = string.Empty;
    public int InsnStart { get; init; }
    public int InsnCount { get; init; }
    public byte PrologueLength { get; init; }
    public ulong ThunkTarget { get; init; } = Anchor.BadAddr;
    public ulong FirstJumpTarget { get; init; } = Anchor.BadAddr;
    public ulong[] DataRefs { get; init; } = [];
    public FieldAccess[] ThisFields { get; init; } = [];
    public ulong[] ThisCalls { get; init; } = [];
    public FieldAccess[] OtherFields { get; init; } = [];
    public Identity Identity { get; init; } = new();
    public Reinforcement Reinforcement { get; init; } = new();

    public uint Size => (uint)(End - Start);
}

public sealed class SegmentInfo
{
    public const byte TypeCode = 2;
    public const byte TypeData = 3;
    public const byte TypeBss = 9;
    public const byte PermExec = 1;
    public const byte PermWrite = 2;
    public const byte PermRead = 4;

    public ulong Start { get; init; }
    public ulong End { get; init; }
    public string Name { get; init; } = string.Empty;
    public byte Type { get; init; }
    public byte Perm { get; init; }
    public byte[]? Bytes { get; init; }

    public bool IsCode => Type == TypeCode;

    public bool Contains(ulong ea) => ea >= Start && ea < End;
}

public sealed class VTableEntry
{
    public string Name { get; init; } = string.Empty;
    public string Demangled { get; init; } = string.Empty;
    public ulong StartEa { get; init; }
    public List<ulong> Slots { get; } = [];
}

public sealed class GlobalIndex
{
    public string BinaryName { get; init; } = string.Empty;
    public bool Is64Bit { get; init; }
    public bool IsLinux { get; init; }
    public ulong ImageBase { get; init; }
    public int PointerSize => Is64Bit ? 8 : 4;

    public FunctionInfo[] Functions { get; init; } = [];
    public InsnRecord[] Instructions { get; init; } = [];
    public SegmentInfo[] Segments { get; init; } = [];
    public SegmentInfo[] CodeSections { get; init; } = [];

    public Dictionary<ulong, FunctionInfo> ByStart { get; init; } = [];

    public Dictionary<string, List<ulong>> StringToFuncs { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<ulong, List<string>> FuncToStrings { get; init; } = [];

    public Dictionary<ulong, List<ulong>> Callers { get; init; } = [];
    public Dictionary<ulong, List<ulong>> Callees { get; init; } = [];

    public Dictionary<string, VTableEntry> VTables { get; init; } = new(StringComparer.Ordinal);
    public Dictionary<ulong, List<VTableRef>> FuncToVTables { get; init; } = [];
    public Dictionary<string, string> ClassToVtName { get; init; } = new(StringComparer.Ordinal);

    public List<DataFuncPtr> DataFuncPtrs { get; init; } = [];
    public Dictionary<ulong, List<ulong>> FuncToDataSegPtrs { get; init; } = [];

    public HashSet<ulong> LibraryFuncs { get; init; } = [];
    public Dictionary<ulong, string> LibraryNames { get; init; } = [];

    public Dictionary<ulong, string> ConvarQwordToName { get; init; } = [];
    public Dictionary<string, List<ulong>> ConvarNameToFuncs { get; init; } = new(StringComparer.Ordinal);

    public Dictionary<ulong, List<ulong>> DataRefToFuncs { get; init; } = [];

    private ulong[] _starts = [];

    internal void Seal() => _starts = [.. Functions.Select(f => f.Start)];

    public FunctionInfo? FuncByStart(ulong ea) => ByStart.GetValueOrDefault(ea);

    public FunctionInfo? FuncAt(ulong ea)
    {
        int i = Array.BinarySearch(_starts, ea);
        if (i < 0)
        {
            i = ~i - 1;
        }

        if (i < 0)
        {
            return null;
        }

        var f = Functions[i];
        return ea < f.End ? f : null;
    }

    public ReadOnlySpan<InsnRecord> Insns(FunctionInfo f) => Instructions.AsSpan(f.InsnStart, f.InsnCount);

    public uint CallerCount(ulong fea) => Callers.TryGetValue(fea, out var l) ? (uint)l.Count : 0;

    public uint CalleeCount(ulong fea) => Callees.TryGetValue(fea, out var l) ? (uint)l.Count : 0;

    public uint Fanout(ulong fea) => CallerCount(fea) + CalleeCount(fea);

    public IReadOnlyList<ulong> CollectDataXrefs(ulong fea) => ByStart.TryGetValue(fea, out var f) ? f.DataRefs : [];

    public IReadOnlyList<ulong> FunctionsReferencingData(ulong dataEa) =>
        DataRefToFuncs.TryGetValue(dataEa, out var l) ? l : [];

    public SegmentInfo? SegmentAt(ulong ea)
    {
        int lo = 0;
        int hi = Segments.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var s = Segments[mid];
            if (ea < s.Start)
            {
                hi = mid - 1;
            }
            else if (ea >= s.End)
            {
                lo = mid + 1;
            }
            else
            {
                return s;
            }
        }

        return null;
    }

    public ReadOnlySpan<byte> ReadBytes(ulong ea, int length)
    {
        var s = SegmentAt(ea);
        if (s?.Bytes == null)
        {
            return [];
        }

        ulong off = ea - s.Start;
        if (off >= (ulong)s.Bytes.Length)
        {
            return [];
        }

        int avail = (int)Math.Min((ulong)length, (ulong)s.Bytes.Length - off);
        return s.Bytes.AsSpan((int)off, avail);
    }

    public ulong ReadPointer(ulong ea)
    {
        var b = ReadBytes(ea, PointerSize);
        if (b.Length < PointerSize)
        {
            return 0;
        }

        return Is64Bit ? BinaryPrimitives.ReadUInt64LittleEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public uint ReadDword(ulong ea)
    {
        var b = ReadBytes(ea, 4);
        return b.Length < 4 ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public bool IsFuncStart(ulong ea) => ByStart.ContainsKey(ea);
}
