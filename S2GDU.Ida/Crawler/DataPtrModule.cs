using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class DataPtrModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        foreach (var (ptrEa, funcEa) in index.DataFuncPtrs)
        {
            if (funcEa != fea)
            {
                continue;
            }

            var seg = index.SegmentAt(ptrEa);
            if (seg == null)
            {
                continue;
            }

            anchors.Add(new Anchor
            {
                Priority = ModulePriority.DataPtr,
                ResolvedEa = fea,
                Name = seg.Name,
                Rva = ptrEa - seg.Start,
            });
        }

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
