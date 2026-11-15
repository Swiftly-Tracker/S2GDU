using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Crawler;

internal static class VTableModule
{
    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        if (!index.FuncToVTables.TryGetValue(fea, out var refs) || refs.Count == 0)
        {
            return anchors;
        }

        foreach (var (vtname, slot) in refs)
        {
            if (!index.VTables.TryGetValue(vtname, out var vt))
            {
                continue;
            }

            var slots = vt.Slots;

            string rawName = vt.Demangled.Length > 0 ? vt.Demangled : vtname;
            var a = new Anchor
            {
                Priority = ModulePriority.VTable,
                Name = RttiNames.NormalizeVTableName(rawName),
                Index = slot,
                VTableSize = (uint)slots.Count,
                ResolvedEa = fea,
            };

            if (vt.StartEa != Anchor.BadAddr)
            {
                a.Rva = vt.StartEa - index.ImageBase;
            }

            if (slot > 0 && slot - 1 < slots.Count && index.ByStart.TryGetValue(slots[(int)slot - 1], out var nb0))
            {
                a.VTableNeighborBefore = nb0.Size;
            }

            if (slot + 1 < (uint)slots.Count && index.ByStart.TryGetValue(slots[(int)slot + 1], out var nb1))
            {
                a.VTableNeighborAfter = nb1.Size;
            }

            anchors.Add(a);
        }

        anchors.Sort((a, b) =>
        {
            if (a.Index != b.Index)
            {
                return a.Index.CompareTo(b.Index);
            }

            return b.VTableSize.CompareTo(a.VTableSize);
        });

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
