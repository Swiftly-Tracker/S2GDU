using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class ConvarFinder
{
    public static FinderResult FindByConvar(Anchor anchor, GlobalIndex index)
    {
        const ModulePriority source = ModulePriority.ConVar;

        if (anchor.Name.Length == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (!index.ConvarNameToFuncs.TryGetValue(anchor.Name, out var funcs) || funcs.Count == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (funcs.Count == 1)
        {
            return new FinderResult(funcs[0], source, "convar: " + anchor.Name);
        }

        return new FinderResult(Anchor.BadAddr, source, string.Empty);
    }
}
