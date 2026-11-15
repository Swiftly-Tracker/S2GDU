using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class XrefFinder
{
    public static List<FinderResult> FindByXrefAll(Anchor anchor, GlobalIndex index)
    {
        var results = new List<FinderResult>();

        if (anchor.ChainDepth == 0 || anchor.Name.Length == 0)
        {
            return results;
        }

        ulong landmarkEa = CallChainFinder.FindLandmarkEa(anchor, index);
        if (landmarkEa == Anchor.BadAddr)
        {
            return results;
        }

        var currentFuncs = new HashSet<ulong> { landmarkEa };
        var allVisited = new HashSet<ulong> { landmarkEa };

        for (byte d = 0; d < anchor.ChainDepth; d++)
        {
            var nextFuncs = new HashSet<ulong>();

            foreach (ulong funcEa in currentFuncs)
            {
                var dataRefs = index.CollectDataXrefs(funcEa);
                uint refCount = 0;
                foreach (ulong dataEa in dataRefs)
                {
                    if (++refCount > Config.XrefMaxDataRefs)
                    {
                        break;
                    }

                    foreach (ulong other in index.FunctionsReferencingData(dataEa))
                    {
                        if (allVisited.Add(other))
                        {
                            nextFuncs.Add(other);
                        }
                    }
                }
            }

            currentFuncs = nextFuncs;
            if (currentFuncs.Count == 0)
            {
                break;
            }

            if (allVisited.Count > 500)
            {
                break;
            }
        }

        string lmType = anchor.ChainLandmarkType switch { 0 => "str", 1 => "vt", 2 => "cv", _ => "dp" };

        foreach (ulong candidate in currentFuncs)
        {
            var f = index.FuncByStart(candidate);
            if (f == null || index.LibraryFuncs.Contains(f.Start))
            {
                continue;
            }

            if (!SizeOk(index, anchor, f.Start))
            {
                continue;
            }

            results.Add(new FinderResult(f.Start, ModulePriority.Xref, $"xref({lmType},d={anchor.ChainDepth}): {anchor.Name}"));
        }

        return results;
    }

    private static bool SizeOk(GlobalIndex index, Anchor anchor, ulong candidateEa)
    {
        if (anchor.FuncSize == 0)
        {
            return true;
        }

        var cf = index.FuncByStart(candidateEa);
        if (cf == null)
        {
            return false;
        }

        uint candSize = cf.Size;
        uint orig = anchor.FuncSize;
        uint factor = orig < 64 ? 4u : 2u;
        uint lo = orig / (factor + 1);
        uint hi = orig * (factor + 1);
        return candSize >= lo && candSize <= hi;
    }
}
