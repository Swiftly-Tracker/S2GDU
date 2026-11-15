using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Pathfinder;

internal static class VTableFinder
{
    private readonly record struct SlotCandidate(int Slot, ulong FuncEa, int NeighborScore);

    public static List<FinderResult> FindByVTableAll(Anchor anchor, GlobalIndex index)
    {
        var results = new List<FinderResult>();

        if (anchor.Name.Length == 0)
        {
            return results;
        }

        VTableEntry? vt = null;

        if (index.ClassToVtName.TryGetValue(anchor.Name, out string? vtnameByClass) && index.VTables.TryGetValue(vtnameByClass, out var vtByClass))
        {
            vt = vtByClass;
        }

        if (vt == null && index.VTables.TryGetValue(anchor.Name, out var vtByName))
        {
            vt = vtByName;
        }

        if (vt == null)
        {
            foreach (var (vtn, candidate) in index.VTables)
            {
                string normDemangled = candidate.Demangled.Length > 0 ? RttiNames.NormalizeVTableName(candidate.Demangled) : string.Empty;
                if ((normDemangled.Length > 0 && normDemangled == anchor.Name) || vtn == anchor.Name)
                {
                    vt = candidate;
                    break;
                }
            }
        }

        if (vt == null)
        {
            return results;
        }

        var slots = vt.Slots;
        uint newVtableSize = (uint)slots.Count;
        uint sizeDiff = anchor.VTableSize > newVtableSize ? anchor.VTableSize - newVtableSize : newVtableSize - anchor.VTableSize;
        int tolerance = (int)(Config.VTableSlotBaseTolerance + sizeDiff);

        int start = Math.Max(0, (int)anchor.Index - tolerance);
        int end = Math.Min(slots.Count, (int)anchor.Index + tolerance + 1);

        bool hasNeighborInfo = anchor.VTableNeighborBefore > 0 || anchor.VTableNeighborAfter > 0;

        var slotCandidates = new List<SlotCandidate>();

        for (int s = start; s < end; s++)
        {
            ulong funcEa = slots[s];
            var f = index.FuncByStart(funcEa);
            if (f == null || index.LibraryFuncs.Contains(f.Start))
            {
                continue;
            }

            int score = 0;
            if (hasNeighborInfo)
            {
                if (anchor.VTableNeighborBefore > 0 && s > 0 && s - 1 < slots.Count)
                {
                    score += GetNbLevel(GetRealFuncSize(index, slots[s - 1]), anchor.VTableNeighborBefore);
                }

                if (anchor.VTableNeighborAfter > 0 && s + 1 < slots.Count)
                {
                    score += GetNbLevel(GetRealFuncSize(index, slots[s + 1]), anchor.VTableNeighborAfter);
                }
            }

            int dist = Math.Abs(s - (int)anchor.Index);
            if (dist == 0)
            {
                score += 2;
            }
            else if (dist <= 2)
            {
                score += 1;
            }

            slotCandidates.Add(new SlotCandidate(s, f.Start, score));
        }

        foreach (var sc in slotCandidates)
        {
            string detail = sc.Slot == (int)anchor.Index
                ? $"vtable: {anchor.Name}[{anchor.Index}]"
                : $"vtable~: {anchor.Name}[{anchor.Index}->{sc.Slot}]";
            results.Add(new FinderResult(sc.FuncEa, ModulePriority.VTable, detail));

            for (int i = 0; i < sc.NeighborScore; i++)
            {
                results.Add(new FinderResult(sc.FuncEa, ModulePriority.VTable, $"vtable_score: {anchor.Name}[{sc.Slot}](rank={i + 1})"));
            }
        }

        return results;
    }

    private static uint GetRealFuncSize(GlobalIndex index, ulong ea)
    {
        var f = index.FuncByStart(ea);
        if (f == null)
        {
            return 0;
        }

        if (f.Size < 32 && f.FirstJumpTarget != Anchor.BadAddr)
        {
            var target = index.FuncAt(f.FirstJumpTarget);
            if (target != null)
            {
                return target.Size;
            }
        }

        return f.Size;
    }

    private static int GetNbLevel(uint actual, uint expected)
    {
        if (expected == 0 || actual == 0)
        {
            return 0;
        }

        uint diff = actual > expected ? actual - expected : expected - actual;
        if (diff <= 2)
        {
            return 10;
        }

        if (diff <= expected * 10 / 100 + 2)
        {
            return 5;
        }

        if (diff <= expected * 30 / 100 + 4)
        {
            return 2;
        }

        return 0;
    }
}
