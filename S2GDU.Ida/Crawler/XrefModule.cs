using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class XrefModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        uint trackedSize = index.FuncByStart(fea)?.Size ?? 0;

        var dataRefs = index.CollectDataXrefs(fea);
        if (dataRefs.Count == 0)
        {
            return anchors;
        }

        int dataRefLimit = Math.Min(dataRefs.Count, (int)Config.XrefMaxDataRefs);

        var visitedFuncs = new HashSet<ulong> { fea };
        var currentFrontier = new List<ulong>();

        for (int i = 0; i < dataRefLimit; i++)
        {
            foreach (ulong otherFea in index.FunctionsReferencingData(dataRefs[i]))
            {
                if (otherFea == fea)
                {
                    continue;
                }

                if (visitedFuncs.Add(otherFea))
                {
                    currentFrontier.Add(otherFea);
                }
            }
        }

        for (byte depth = 1; depth <= Config.XrefMaxDepth; depth++)
        {
            if (currentFrontier.Count == 0 || anchors.Count >= Config.XrefMaxAnchors)
            {
                break;
            }

            var nextFrontier = new List<ulong>();

            foreach (ulong frontierEa in currentFrontier)
            {
                if (anchors.Count >= Config.XrefMaxAnchors)
                {
                    break;
                }

                var lm = CallChainModule.DetectLandmark(frontierEa, index);
                if (lm.Name.Length > 0)
                {
                    anchors.Add(new Anchor
                    {
                        Priority = ModulePriority.Xref,
                        Name = lm.Name,
                        ChainDepth = depth,
                        ChainDirections = 0,
                        ChainLandmarkType = lm.Type,
                        Fanout = index.Fanout(frontierEa),
                        FuncSize = trackedSize,
                        ResolvedEa = frontierEa,
                    });
                    continue;
                }

                if (depth < Config.XrefMaxDepth)
                {
                    var nextDataRefs = index.CollectDataXrefs(frontierEa);
                    int refCount = 0;
                    foreach (ulong dataEa in nextDataRefs)
                    {
                        if (++refCount > Config.XrefMaxDataRefs)
                        {
                            break;
                        }

                        foreach (ulong other in index.FunctionsReferencingData(dataEa))
                        {
                            if (visitedFuncs.Add(other))
                            {
                                nextFrontier.Add(other);
                            }
                        }
                    }
                }
            }

            currentFrontier = nextFrontier;
            if (visitedFuncs.Count > 500)
            {
                break;
            }
        }

        anchors.Sort((a, b) =>
        {
            if (a.ChainDepth != b.ChainDepth)
            {
                return a.ChainDepth.CompareTo(b.ChainDepth);
            }

            return a.ChainLandmarkType.CompareTo(b.ChainLandmarkType);
        });

        if (anchors.Count > Config.XrefMaxAnchors)
        {
            anchors.RemoveRange((int)Config.XrefMaxAnchors, anchors.Count - (int)Config.XrefMaxAnchors);
        }

        return anchors;
    }
}
