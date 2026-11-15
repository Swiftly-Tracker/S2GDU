using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

internal static class LibraryModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        if (!index.Callees.TryGetValue(fea, out var callees))
        {
            return anchors;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (ulong callee in callees)
        {
            if (!index.LibraryFuncs.Contains(callee))
            {
                continue;
            }

            if (!index.LibraryNames.TryGetValue(callee, out string? name))
            {
                continue;
            }

            if (!seen.Add(name))
            {
                continue;
            }

            anchors.Add(new Anchor { Priority = ModulePriority.Library, Name = name, ResolvedEa = callee, Fanout = index.Fanout(callee) });
        }

        anchors.Sort((a, b) => a.Fanout.CompareTo(b.Fanout));

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
