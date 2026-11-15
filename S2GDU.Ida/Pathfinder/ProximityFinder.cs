using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class ProximityFinder
{
    public static FinderResult FindByProximity(Anchor anchor, GlobalIndex index)
    {
        const ModulePriority source = ModulePriority.Proximity;

        if (anchor.Name.Length == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (!index.StringToFuncs.TryGetValue(anchor.Name, out var funcs) || funcs.Count != 1)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        ulong neighborEa = funcs[0];
        long delta = (long)anchor.Rva;
        ulong predicted = (ulong)((long)neighborEa + delta);

        ulong candidate = Anchor.BadAddr;

        var f = index.FuncAt(predicted);
        if (f != null)
        {
            candidate = f.Start;
        }
        else
        {
            ulong searchStart = predicted > Config.ProximityDeltaTolerance ? predicted - Config.ProximityDeltaTolerance : 0;
            ulong searchEnd = predicted + Config.ProximityDeltaTolerance;

            ulong best = Anchor.BadAddr;
            ulong bestDist = ulong.MaxValue;

            foreach (ulong start in NextFuncStartsAfter(index, searchStart))
            {
                if (start >= searchEnd)
                {
                    break;
                }

                ulong dist = start > predicted ? start - predicted : predicted - start;
                if (dist < bestDist)
                {
                    bestDist = dist;
                    best = start;
                }
            }

            if (best != Anchor.BadAddr)
            {
                candidate = best;
            }
        }

        if (candidate == Anchor.BadAddr)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        return new FinderResult(candidate, source, $"proximity: neighbor={anchor.Name} delta={delta}");
    }

    private static IEnumerable<ulong> NextFuncStartsAfter(GlobalIndex index, ulong afterEa)
    {
        var funcs = index.Functions;
        int lo = 0, hi = funcs.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (funcs[mid].Start <= afterEa)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        for (int i = lo; i < funcs.Length; i++)
        {
            yield return funcs[i].Start;
        }
    }
}
