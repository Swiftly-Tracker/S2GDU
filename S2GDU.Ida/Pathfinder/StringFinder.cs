using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

internal static class StringFinder
{
    public static FinderResult FindByString(Anchor anchor, GlobalIndex index)
    {
        const ModulePriority source = ModulePriority.UniqueStr;

        if (anchor.Name.Length == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (!index.StringToFuncs.TryGetValue(anchor.Name, out var funcs) || funcs.Count == 0)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        int refCount = funcs.Count;

        if (refCount == 1)
        {
            return new FinderResult(funcs[0], source, "unique_string: " + anchor.Name);
        }

        if (refCount > Config.MaxRareStringRefs)
        {
            return new FinderResult(Anchor.BadAddr, source, string.Empty);
        }

        if (anchor.Rva > 0)
        {
            uint expectedSize = (uint)anchor.Rva;
            ulong best = Anchor.BadAddr;
            uint bestDiff = uint.MaxValue;
            int countClose = 0;

            foreach (ulong fea in funcs)
            {
                var f = index.FuncByStart(fea);
                if (f == null)
                {
                    continue;
                }

                uint actualSize = f.Size;
                uint diff = expectedSize > actualSize ? expectedSize - actualSize : actualSize - expectedSize;

                if (diff <= expectedSize * 30 / 100)
                {
                    countClose++;
                    if (diff < bestDiff)
                    {
                        bestDiff = diff;
                        best = fea;
                    }
                }
            }

            if (refCount <= 3 && best != Anchor.BadAddr)
            {
                string suffix = countClose == 1 ? ",unique_size" : ",best_size";
                return new FinderResult(best, source, $"rare_string({refCount}{suffix}): {anchor.Name}");
            }

            if (countClose == 1 && best != Anchor.BadAddr)
            {
                return new FinderResult(best, source, $"rare_string({refCount}): {anchor.Name}");
            }
        }

        return new FinderResult(Anchor.BadAddr, source, string.Empty);
    }
}
