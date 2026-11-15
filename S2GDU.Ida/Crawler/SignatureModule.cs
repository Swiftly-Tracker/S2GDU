using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Signatures;

namespace S2GDU.Ida.Crawler;

internal static class SignatureModule
{
    private const ulong BadAddr = ulong.MaxValue;

    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        var sigStart = SigGen.Make(index, fea, fea, 0);
        if (!sigStart.IsEmpty)
        {
            anchors.Add(new Anchor { Priority = ModulePriority.Signature, Signature = sigStart, ResolvedEa = fea });
        }

        var f = index.FuncByStart(fea);
        if (f != null && f.End - fea > Config.MinFuncSizeForSkip)
        {
            byte prologueLen = SigGen.DetectPrologueLength(index, fea);
            if (prologueLen > 0)
            {
                ulong skipEa = fea + prologueLen;
                var sigSkip = SigGen.Make(index, skipEa, skipEa, prologueLen);
                if (!sigSkip.IsEmpty)
                {
                    bool isDup = sigStart.Bytes.SequenceEqual(sigSkip.Bytes);
                    if (!isDup)
                    {
                        anchors.Add(new Anchor { Priority = ModulePriority.Signature, Signature = sigSkip, ResolvedEa = fea });
                    }
                }
            }
        }

        anchors.Sort((a, b) => b.Signature.Length.CompareTo(a.Signature.Length));

        if (anchors.Count > Config.MaxItemsPerModule)
        {
            anchors.RemoveRange((int)Config.MaxItemsPerModule, anchors.Count - (int)Config.MaxItemsPerModule);
        }

        return anchors;
    }
}
