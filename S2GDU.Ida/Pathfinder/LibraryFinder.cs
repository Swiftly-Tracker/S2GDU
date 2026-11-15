using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class LibraryFinder
{
    public static FinderResult FindByLibrary(Anchor anchor, GlobalIndex index)
    {
        const ModulePriority source = ModulePriority.Library;

        if (anchor.Name.Length == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        ulong libEa = Anchor.BadAddr;
        foreach (var (ea, name) in index.LibraryNames)
        {
            if (name == anchor.Name)
            {
                libEa = ea;
                break;
            }
        }

        if (libEa == Anchor.BadAddr)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (!index.Callers.TryGetValue(libEa, out var callers) || callers.Count == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (callers.Count == 1)
        {
            ulong caller = callers[0];
            if (index.FuncByStart(caller) != null && !index.LibraryFuncs.Contains(caller))
            {
                return new FinderResult(caller, source, "library_single_caller: " + anchor.Name);
            }
        }
        else if (callers.Count <= 3)
        {
            foreach (ulong caller in callers)
            {
                if (!index.LibraryFuncs.Contains(caller) && index.FuncByStart(caller) != null)
                {
                    return new FinderResult(caller, source, $"library_few_callers({callers.Count}): {anchor.Name}");
                }
            }
        }

        return new FinderResult(Anchor.BadAddr, source, string.Empty);
    }
}
