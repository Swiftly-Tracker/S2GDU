using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class ProximityModule
{
    private readonly record struct Candidate(string UniqueStr, long Delta, uint NeighborSize);

    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        ulong searchStart = fea > Config.MaxNeighborDistance ? fea - Config.MaxNeighborDistance : 0;
        ulong searchEnd = fea + Config.MaxNeighborDistance;

        var candidates = new List<Candidate>();

        foreach (var (str, funcs) in index.StringToFuncs)
        {
            if (funcs.Count != 1)
            {
                continue;
            }

            if (str.Length < Config.MinProximityStringLength)
            {
                continue;
            }

            ulong neighborEa = funcs[0];
            if (neighborEa == fea || neighborEa < searchStart || neighborEa > searchEnd)
            {
                continue;
            }

            var nf = index.FuncByStart(neighborEa);
            if (nf == null)
            {
                continue;
            }

            candidates.Add(new Candidate(str, (long)fea - (long)neighborEa, nf.Size));
        }

        candidates.Sort((a, b) => Math.Abs(a.Delta).CompareTo(Math.Abs(b.Delta)));

        int limit = Math.Min(candidates.Count, (int)Config.MaxItemsPerModule);
        var anchors = new List<Anchor>(limit);
        for (int i = 0; i < limit; i++)
        {
            anchors.Add(new Anchor
            {
                Priority = ModulePriority.Proximity,
                Name = candidates[i].UniqueStr,
                Rva = (ulong)candidates[i].Delta,
                Index = candidates[i].NeighborSize,
                ResolvedEa = fea,
            });
        }

        return anchors;
    }
}
