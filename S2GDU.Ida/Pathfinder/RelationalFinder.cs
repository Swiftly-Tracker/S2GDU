using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Signatures;

namespace S2GDU.Ida.Pathfinder;

internal static class RelationalFinder
{
    public static List<FinderResult> FindByRelationalAll(Anchor anchor, GlobalIndex index)
    {
        var results = new List<FinderResult>();

        if (anchor.Signature.IsEmpty || anchor.Name.Length == 0)
        {
            return results;
        }

        bool isCaller = anchor.Name.StartsWith("CALLER:", StringComparison.Ordinal);
        bool isCallee = anchor.Name.StartsWith("CALLEE:", StringComparison.Ordinal);
        if (!isCaller && !isCallee)
        {
            return results;
        }

        ulong anchorEa = SigGen.FindFirstMatch(index, anchor.Signature, 0, Anchor.BadAddr);
        if (anchorEa == Anchor.BadAddr)
        {
            return results;
        }

        ulong second = SigGen.FindFirstMatch(index, anchor.Signature, anchorEa + 1, Anchor.BadAddr);
        if (second != Anchor.BadAddr)
        {
            return results;
        }

        if (anchorEa < anchor.Signature.Offset)
        {
            return results;
        }

        anchorEa -= anchor.Signature.Offset;
        var anchorFunc = index.FuncAt(anchorEa);
        if (anchorFunc == null)
        {
            return results;
        }

        anchorEa = anchorFunc.Start;

        if (isCaller)
        {
            if (!index.Callees.TryGetValue(anchorEa, out var callees))
            {
                return results;
            }

            if (callees.Count <= 10)
            {
                foreach (ulong callee in callees)
                {
                    if (!index.LibraryFuncs.Contains(callee))
                    {
                        results.Add(new FinderResult(callee, ModulePriority.Relational, "relational_caller→callee: " + anchor.Name));
                    }
                }
            }
        }
        else
        {
            if (!index.Callers.TryGetValue(anchorEa, out var callers))
            {
                return results;
            }

            if (callers.Count <= 10)
            {
                foreach (ulong caller in callers)
                {
                    if (!index.LibraryFuncs.Contains(caller))
                    {
                        results.Add(new FinderResult(caller, ModulePriority.Relational, "relational_callee→caller: " + anchor.Name));
                    }
                }
            }
        }

        return results;
    }

    public static List<FinderResult> FindByRelationalMatchedAll(Anchor anchor, GlobalIndex index, IReadOnlyDictionary<ulong, ulong> matchedMap)
    {
        var results = new List<FinderResult>();

        if (anchor.Name.Length == 0)
        {
            return results;
        }

        bool isCaller = anchor.Name.StartsWith("CALLER:", StringComparison.Ordinal);
        bool isCallee = anchor.Name.StartsWith("CALLEE:", StringComparison.Ordinal);
        if (!isCaller && !isCallee)
        {
            return results;
        }

        if (!matchedMap.TryGetValue(anchor.ResolvedEa, out ulong anchorNewEa))
        {
            return results;
        }

        if (isCaller)
        {
            if (index.Callees.TryGetValue(anchorNewEa, out var callees))
            {
                foreach (ulong callee in callees)
                {
                    if (!index.LibraryFuncs.Contains(callee))
                    {
                        results.Add(new FinderResult(callee, ModulePriority.Relational, "relational_matched_caller→callee: " + anchor.Name));
                    }
                }
            }
        }
        else
        {
            if (index.Callers.TryGetValue(anchorNewEa, out var callers))
            {
                foreach (ulong caller in callers)
                {
                    if (!index.LibraryFuncs.Contains(caller))
                    {
                        results.Add(new FinderResult(caller, ModulePriority.Relational, "relational_matched_callee→caller: " + anchor.Name));
                    }
                }
            }
        }

        return results;
    }
}
