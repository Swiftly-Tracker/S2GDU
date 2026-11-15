using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Signatures;

namespace S2GDU.Ida.Pathfinder;

internal static class SignatureFinder
{
    public static FinderResult FindBySignature(Anchor anchor, GlobalIndex index)
    {
        if (anchor.Signature.IsEmpty)
        {
            return new FinderResult(Anchor.BadAddr, ModulePriority.Signature, string.Empty);
        }

        ulong found = SigGen.FindFirstMatch(index, anchor.Signature, 0, Anchor.BadAddr);
        if (found == Anchor.BadAddr)
        {
            return new FinderResult(Anchor.BadAddr, ModulePriority.Signature, string.Empty);
        }

        ulong second = SigGen.FindFirstMatch(index, anchor.Signature, found + 1, Anchor.BadAddr);
        if (second != Anchor.BadAddr)
        {
            return new FinderResult(Anchor.BadAddr, ModulePriority.Signature, string.Empty);
        }

        if (found < anchor.Signature.Offset)
        {
            return new FinderResult(Anchor.BadAddr, ModulePriority.Signature, string.Empty);
        }

        ulong target = found - anchor.Signature.Offset;
        var f = index.FuncAt(target);
        if (f == null || target < f.Start || target >= f.End)
        {
            return new FinderResult(Anchor.BadAddr, ModulePriority.Signature, string.Empty);
        }

        return new FinderResult(f.Start, ModulePriority.Signature, $"sig_match (offset={anchor.Signature.Offset})");
    }
}
