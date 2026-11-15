using Google.Protobuf;
using S2GDU.Ida.Model;
using P = S2GDU.Ida.Model.Proto;

namespace S2GDU.Ida.Storage;

public sealed record ClueFile(string BinaryName, List<TrackedFunc> Functions);

public static class ClueFileStore
{
    public const uint SchemaVersion = 2;
    public const string Extension = ".gdu.pb";

    public static ClueFile Read(string path)
    {
        P.ClueFile file;
        using (var stream = File.OpenRead(path))
        {
            file = P.ClueFile.Parser.ParseFrom(stream);
        }

        if (file.SchemaVersion > SchemaVersion)
        {
            throw new InvalidDataException($"'{path}' uses schema {file.SchemaVersion}; this build reads up to {SchemaVersion}.");
        }

        return new ClueFile(file.BinaryName, [.. file.Functions.Select(FromProto)]);
    }

    public static void Write(string path, ClueFile clue)
    {
        var file = new P.ClueFile { SchemaVersion = SchemaVersion, BinaryName = clue.BinaryName };
        file.Functions.AddRange(clue.Functions.Select(ToProto));

        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (dir != null)
        {
            Directory.CreateDirectory(dir);
        }

        string temp = path + ".tmp";
        using (var stream = File.Create(temp))
        {
            file.WriteTo(stream);
        }

        File.Move(temp, path, overwrite: true);
    }

    private static P.Signature ToProto(Signature s)
    {
        var mask = new byte[s.Mask.Count];
        for (int i = 0; i < mask.Length; i++)
        {
            mask[i] = s.Mask[i] ? (byte)1 : (byte)0;
        }

        return new P.Signature { Pattern = ByteString.CopyFrom([.. s.Bytes]), Mask = ByteString.CopyFrom(mask), Offset = s.Offset };
    }

    private static Signature FromProto(P.Signature? p)
    {
        var s = new Signature();
        if (p == null)
        {
            return s;
        }

        s.Offset = p.Offset;
        s.Bytes.AddRange(p.Pattern.Span);
        foreach (byte m in p.Mask.Span)
        {
            s.Mask.Add(m != 0);
        }

        return s;
    }

    private static P.Identity ToProto(Identity i)
    {
        var p = new P.Identity
        {
            ReturnType = i.ReturnType,
            ParamCount = i.ParamCount,
            HasReturn = i.HasReturn,
            HasIndirectCall = i.HasIndirectCall,
            HasSwitch = i.HasSwitch,
            StructFlags = i.StructFlags,
        };
        p.ParamTypes.AddRange(i.ParamTypes);
        return p;
    }

    private static Identity FromProto(P.Identity? p)
    {
        var i = new Identity();
        if (p == null)
        {
            return i;
        }

        i.ReturnType = p.ReturnType;
        i.ParamCount = (byte)p.ParamCount;
        i.HasReturn = p.HasReturn;
        i.HasIndirectCall = p.HasIndirectCall;
        i.HasSwitch = p.HasSwitch;
        i.StructFlags = p.StructFlags;
        i.ParamTypes.AddRange(p.ParamTypes);
        return i;
    }

    private static P.Reinforcement ToProto(Reinforcement r)
    {
        var p = new P.Reinforcement
        {
            Size = r.Size,
            BbCount = r.BbCount,
            Cyclomatic = r.Cyclomatic,
            CallerCount = r.CallerCount,
            CalleeCount = r.CalleeCount,
        };
        p.Strings.AddRange(r.Strings);
        p.Constants.AddRange(r.Constants);
        return p;
    }

    private static Reinforcement FromProto(P.Reinforcement? p)
    {
        var r = new Reinforcement();
        if (p == null)
        {
            return r;
        }

        r.Size = p.Size;
        r.BbCount = (ushort)p.BbCount;
        r.Cyclomatic = (ushort)p.Cyclomatic;
        r.CallerCount = p.CallerCount;
        r.CalleeCount = p.CalleeCount;
        r.Strings.AddRange(p.Strings);
        r.Constants.AddRange(p.Constants);
        return r;
    }

    private static P.Anchor ToProto(Anchor a) => new()
    {
        Priority = (P.ModulePriority)a.Priority,
        Name = a.Name,
        Signature = ToProto(a.Signature),
        Index = a.Index,
        VtableSize = a.VTableSize,
        VtableNeighborBefore = a.VTableNeighborBefore,
        VtableNeighborAfter = a.VTableNeighborAfter,
        Rva = a.Rva,
        Fanout = a.Fanout,
        ResolvedEa = a.ResolvedEa,
        ChainDepth = a.ChainDepth,
        ChainDirections = a.ChainDirections,
        ChainLandmarkType = a.ChainLandmarkType,
        FuncSize = a.FuncSize,
    };

    private static Anchor FromProto(P.Anchor p) => new()
    {
        Priority = (ModulePriority)p.Priority,
        Name = p.Name,
        Signature = FromProto(p.Signature),
        Index = p.Index,
        VTableSize = p.VtableSize,
        VTableNeighborBefore = p.VtableNeighborBefore,
        VTableNeighborAfter = p.VtableNeighborAfter,
        Rva = p.Rva,
        Fanout = p.Fanout,
        ResolvedEa = p.ResolvedEa,
        ChainDepth = (byte)p.ChainDepth,
        ChainDirections = (byte)p.ChainDirections,
        ChainLandmarkType = (byte)p.ChainLandmarkType,
        FuncSize = p.FuncSize,
    };

    private static P.MatchResult ToProto(MatchResult m) => new()
    {
        Verdict = (P.MatchVerdict)m.Verdict,
        MatchedEa = m.MatchedEa,
        Method = m.Method,
        Votes = m.Votes,
        Structural = m.Structural,
        IdentityPassed = m.IdentityPassed,
        ReinforcementScore = m.ReinforcementScore,
    };

    private static MatchResult FromProto(P.MatchResult? p) => p == null ? new MatchResult() : new MatchResult
    {
        Verdict = (MatchVerdict)p.Verdict,
        MatchedEa = p.MatchedEa,
        Method = p.Method,
        Votes = p.Votes,
        Structural = p.Structural,
        IdentityPassed = p.IdentityPassed,
        ReinforcementScore = p.ReinforcementScore,
    };

    private static P.TrackedFunc ToProto(TrackedFunc t)
    {
        var p = new P.TrackedFunc
        {
            Name = t.Name,
            OriginalEa = t.OriginalEa,
            Identity = ToProto(t.Identity),
            Reinforcement = ToProto(t.Reinforcement),
            ExportSig = ToProto(t.ExportSig),
            TrackingSig = ToProto(t.TrackingSig),
            PrologueLength = t.PrologueLength,
            SigOffset = t.SigOffset,
            VtableClass = t.VTableClass,
            VtableOffset = t.VTableOffset,
            LastMatch = ToProto(t.Match),
        };
        p.Anchors.AddRange(t.Anchors.Select(ToProto));
        p.MidContext.AddRange(t.MidContext.Select(v => (uint)v));
        if (t.FieldOffset >= 0)
        {
            p.FieldOffset = t.FieldOffset;
        }

        return p;
    }

    private static TrackedFunc FromProto(P.TrackedFunc p) => new()
    {
        Name = p.Name,
        OriginalEa = p.OriginalEa,
        Identity = FromProto(p.Identity),
        Reinforcement = FromProto(p.Reinforcement),
        Anchors = [.. p.Anchors.Select(FromProto)],
        ExportSig = FromProto(p.ExportSig),
        TrackingSig = FromProto(p.TrackingSig),
        PrologueLength = (byte)p.PrologueLength,
        SigOffset = p.SigOffset,
        MidContext = [.. p.MidContext.Select(v => (ushort)v)],
        VTableClass = p.VtableClass,
        VTableOffset = p.VtableOffset,
        FieldOffset = p.HasFieldOffset ? p.FieldOffset : -1,
        Match = FromProto(p.LastMatch),
    };
}
