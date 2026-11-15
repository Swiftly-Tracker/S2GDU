using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Signatures;

namespace S2GDU.Ida.Crawler;

internal static class RelationalModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();
        var seen = new HashSet<ulong>();

        if (index.Callers.TryGetValue(fea, out var callers))
        {
            foreach (ulong caller in callers)
            {
                uint fanout = index.Fanout(caller);
                if (fanout > Config.MaxRelationalFanout)
                {
                    continue;
                }

                var cf = index.FuncByStart(caller);
                if (cf != null && Config.IsAntiAnchorName(cf.Name))
                {
                    continue;
                }

                var sig = SigGen.Make(index, caller, caller, 0);
                if (sig.IsEmpty)
                {
                    continue;
                }

                if (!seen.Add(caller))
                {
                    continue;
                }

                anchors.Add(new Anchor
                {
                    Priority = ModulePriority.Relational,
                    Name = "CALLER:" + (cf?.Name ?? string.Empty),
                    Signature = sig,
                    ResolvedEa = caller,
                    Fanout = fanout,
                });
            }
        }

        if (index.Callees.TryGetValue(fea, out var callees))
        {
            foreach (ulong callee in callees)
            {
                uint fanout = index.Fanout(callee);
                if (fanout > Config.MaxRelationalFanout)
                {
                    continue;
                }

                var cf = index.FuncByStart(callee);
                if (cf != null && Config.IsAntiAnchorName(cf.Name))
                {
                    continue;
                }

                var sig = SigGen.Make(index, callee, callee, 0);
                if (sig.IsEmpty)
                {
                    continue;
                }

                if (!seen.Add(callee))
                {
                    continue;
                }

                anchors.Add(new Anchor
                {
                    Priority = ModulePriority.Relational,
                    Name = "CALLEE:" + (cf?.Name ?? string.Empty),
                    Signature = sig,
                    ResolvedEa = callee,
                    Fanout = fanout,
                });
            }
        }

        anchors.Sort((a, b) => a.Fanout.CompareTo(b.Fanout));

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
