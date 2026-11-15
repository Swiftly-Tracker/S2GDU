using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class StringModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        if (!index.FuncToStrings.TryGetValue(fea, out var strs))
        {
            return anchors;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var f = index.FuncByStart(fea);

        foreach (string s in strs)
        {
            if (s.Length < Config.MinStringLength)
            {
                continue;
            }

            if (!seen.Add(s))
            {
                continue;
            }

            if (!index.StringToFuncs.TryGetValue(s, out var funcs))
            {
                continue;
            }

            int refCount = funcs.Count;
            if (refCount == 1)
            {
                anchors.Add(new Anchor
                {
                    Priority = ModulePriority.UniqueStr,
                    Name = s,
                    Index = 1,
                    Rva = f?.Size ?? 0,
                    ResolvedEa = fea,
                });
            }
            else if (refCount >= 2 && refCount <= Config.MaxRareStringRefs)
            {
                anchors.Add(new Anchor
                {
                    Priority = ModulePriority.UniqueStr,
                    Name = s,
                    Index = (uint)refCount,
                    Rva = f?.Size ?? 0,
                    ResolvedEa = fea,
                });
            }
        }

        anchors.Sort((a, b) =>
        {
            if (a.Index != b.Index)
            {
                return a.Index.CompareTo(b.Index);
            }

            return b.Name.Length.CompareTo(a.Name.Length);
        });

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
