using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class DataPtrFinder
{
    private readonly record struct CandidateInfo(ulong PtrEa, ulong FuncEa, ulong Dist);

    public static List<FinderResult> FindByDataPtrAll(Anchor anchor, GlobalIndex index) =>
        FindCore(anchor, index, Config.DataPtrSectionTolerance, "data_ptr", 0);

    public static List<FinderResult> FindByDataPtrCalibratedAll(Anchor anchor, GlobalIndex index, long delta) =>
        FindCore(anchor, index, Config.DataPtrCalTolerance, "data_ptr_cal", delta, calibrated: true);

    private static List<FinderResult> FindCore(Anchor anchor, GlobalIndex index, uint tolerance, string tag, long delta, bool calibrated = false)
    {
        var results = new List<FinderResult>();

        if (anchor.Rva == 0 || anchor.Name.Length == 0)
        {
            return results;
        }

        ulong expectedEa = Anchor.BadAddr;

        foreach (var seg in index.Segments)
        {
            bool match = seg.Name == anchor.Name;
            if (!match && seg.Name.Contains(".data", StringComparison.Ordinal) && anchor.Name.Contains(".data", StringComparison.Ordinal))
            {
                match = true;
            }

            if (!match)
            {
                continue;
            }

            if (!calibrated)
            {
                ulong candidateEa = seg.Start + anchor.Rva;
                if (candidateEa >= seg.Start && candidateEa < seg.End)
                {
                    expectedEa = candidateEa;
                    break;
                }
            }
            else
            {
                long adjustedRva = (long)anchor.Rva + delta;
                if (adjustedRva >= 0 && (ulong)adjustedRva < seg.End - seg.Start)
                {
                    expectedEa = seg.Start + (ulong)adjustedRva;
                    break;
                }
            }
        }

        if (expectedEa == Anchor.BadAddr)
        {
            return results;
        }

        ulong searchStart = expectedEa > tolerance ? expectedEa - tolerance : index.ImageBase;
        ulong searchEnd = expectedEa + tolerance;

        var candidates = new List<CandidateInfo>();
        foreach (var (ptrEa, funcEa) in index.DataFuncPtrs)
        {
            if (ptrEa < searchStart || ptrEa > searchEnd)
            {
                continue;
            }

            var f = index.FuncByStart(funcEa);
            if (f == null || index.LibraryFuncs.Contains(f.Start))
            {
                continue;
            }

            ulong dist = ptrEa > expectedEa ? ptrEa - expectedEa : expectedEa - ptrEa;
            candidates.Add(new CandidateInfo(ptrEa, f.Start, dist));
        }

        candidates.Sort((a, b) => a.Dist.CompareTo(b.Dist));

        var seenFuncs = new HashSet<ulong>();
        foreach (var ci in candidates)
        {
            if (!seenFuncs.Add(ci.FuncEa))
            {
                continue;
            }

            string detail = calibrated
                ? $"{tag}: {anchor.Name}+0x{anchor.Rva:X} (delta=({delta})) (residual={(long)ci.PtrEa - (long)expectedEa})"
                : $"{tag}: {anchor.Name}+0x{anchor.Rva:X} (delta={(long)ci.PtrEa - (long)expectedEa})";

            results.Add(new FinderResult(ci.FuncEa, ModulePriority.DataPtr, detail));
            if (!calibrated && results.Count >= Config.DataPtrCalMaxCandidates)
            {
                break;
            }
        }

        return results;
    }

    public static long CalibrateDataPtrDelta(GlobalIndex index, IReadOnlyList<TrackedFunc> funcs)
    {
        var deltas = new List<long>();

        foreach (var tf in funcs)
        {
            if (tf.Match.Verdict != MatchVerdict.Match)
            {
                continue;
            }

            foreach (var anchor in tf.Anchors)
            {
                if (anchor.Priority != ModulePriority.DataPtr || anchor.Rva == 0 || anchor.Name.Length == 0)
                {
                    continue;
                }

                foreach (var (ptrEa, funcEa) in index.DataFuncPtrs)
                {
                    if (funcEa != tf.Match.MatchedEa)
                    {
                        continue;
                    }

                    var seg = index.SegmentAt(ptrEa);
                    if (seg == null || seg.Name != anchor.Name)
                    {
                        continue;
                    }

                    long newRva = (long)(ptrEa - seg.Start);
                    long oldRva = (long)anchor.Rva;
                    deltas.Add(newRva - oldRva);
                    break;
                }
            }
        }

        if (deltas.Count == 0)
        {
            return 0;
        }

        deltas.Sort();
        return deltas[deltas.Count / 2];
    }
}
