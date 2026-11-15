using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class ConvarModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        foreach (ulong dataEa in index.CollectDataXrefs(fea))
        {
            if (!index.ConvarQwordToName.TryGetValue(dataEa, out string? convarName))
            {
                continue;
            }

            if (!index.ConvarNameToFuncs.TryGetValue(convarName, out var funcs))
            {
                continue;
            }

            if (funcs.Count == 1 && funcs[0] == fea)
            {
                if (!seenNames.Add(convarName))
                {
                    continue;
                }

                anchors.Add(new Anchor { Priority = ModulePriority.ConVar, Name = convarName, ResolvedEa = fea });
            }
        }

        anchors.Sort((a, b) => b.Name.Length.CompareTo(a.Name.Length));

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
