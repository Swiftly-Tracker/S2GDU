using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Signatures;

public static class SigGen
{
    private const ulong BadAddr = ulong.MaxValue;

    public static void Trim(Signature sig)
    {
        int end = sig.Mask.Count;
        while (end > 0 && !sig.Mask[end - 1])
        {
            end--;
        }

        sig.Bytes.RemoveRange(end, sig.Bytes.Count - end);
        sig.Mask.RemoveRange(end, sig.Mask.Count - end);

        int leading = 0;
        while (leading < sig.Mask.Count && !sig.Mask[leading])
        {
            leading++;
        }

        if (leading > 0)
        {
            sig.Bytes.RemoveRange(0, leading);
            sig.Mask.RemoveRange(0, leading);
            sig.Offset += (uint)leading;
        }
    }

    public static ulong FindFirstMatch(GlobalIndex index, Signature sig, ulong startAt, ulong ignoreEa)
    {
        if (sig.IsEmpty)
        {
            return BadAddr;
        }

        var pattern = new Pattern(sig);
        foreach (var sec in index.CodeSections)
        {
            var data = sec.Bytes!;
            if (startAt >= sec.Start + (ulong)data.Length)
            {
                continue;
            }

            int from = startAt > sec.Start ? (int)(startAt - sec.Start) : 0;
            int hit = pattern.Next(data, from, sec.Start, ignoreEa);
            if (hit >= 0)
            {
                return sec.Start + (ulong)hit;
            }
        }

        return BadAddr;
    }

    public static List<ulong> FindAll(GlobalIndex index, Signature sig, int limit = int.MaxValue)
    {
        var hits = new List<ulong>();
        if (sig.IsEmpty)
        {
            return hits;
        }

        var pattern = new Pattern(sig);
        foreach (var sec in index.CodeSections)
        {
            var data = sec.Bytes!;
            int from = 0;
            while (hits.Count < limit)
            {
                int hit = pattern.Next(data, from, sec.Start, BadAddr);
                if (hit < 0)
                {
                    break;
                }

                hits.Add(sec.Start + (ulong)hit);
                from = hit + 1;
            }
        }

        return hits;
    }

    public static Signature Make(GlobalIndex index, ulong startEa, ulong ignoreEa, uint offset)
    {
        var f = index.FuncAt(startEa);
        if (f == null)
        {
            return new Signature();
        }

        var insns = index.Insns(f);
        int i = IndexOfInsn(insns, (uint)(startEa - f.Start));
        if (i < 0)
        {
            return new Signature();
        }

        var sig = new Signature { Offset = offset };
        ulong lastFound = 0;
        for (; i < insns.Length; i++)
        {
            var insn = insns[i];
            ulong ea = f.Start + insn.Delta;
            var raw = index.ReadBytes(ea, insn.Size);
            if (raw.Length < insn.Size || insn.Size == 0)
            {
                break;
            }

            for (int b = 0; b < raw.Length; b++)
            {
                sig.Bytes.Add(raw[b]);
                sig.Mask.Add(!(insn.ImmOffset > 0 && b >= insn.ImmOffset));
            }

            if (raw[0] is 0xCC or 0x90)
            {
                break;
            }

            if (sig.Length >= Config.MinSignatureLength)
            {
                ulong found = FindFirstMatch(index, sig, lastFound, ignoreEa);
                if (found == BadAddr)
                {
                    break;
                }

                lastFound = found;
            }
        }

        Trim(sig);
        return sig.Length < Config.MinSignatureLength ? new Signature() : sig;
    }

    public static byte DetectPrologueLength(GlobalIndex index, ulong fea) =>
        index.FuncByStart(fea)?.PrologueLength ?? 0;

    public static List<ushort> CollectMidContext(GlobalIndex index, FunctionInfo f, ulong targetEa, uint radius)
    {
        var insns = index.Insns(f);
        if (insns.Length == 0 || targetEa < f.Start || targetEa >= f.End)
        {
            return [];
        }

        uint delta = (uint)(targetEa - f.Start);
        int target = -1;
        for (int i = 0; i < insns.Length; i++)
        {
            uint end = i + 1 < insns.Length ? insns[i + 1].Delta : f.Size;
            if (delta >= insns[i].Delta && delta < end)
            {
                target = i;
                break;
            }
        }

        if (target < 0)
        {
            return [];
        }

        int window = (int)(2 * radius + 1);
        var ctx = new List<ushort>(window);
        for (int i = 0; i < window; i++)
        {
            int idx = target - (int)radius + i;
            ctx.Add(idx >= 0 && idx < insns.Length ? insns[idx].Itype : Config.MidContextNone);
        }

        return ctx;
    }

    public static ulong FindMidContextMatch(GlobalIndex index, FunctionInfo f, IReadOnlyList<ushort> context, uint radius, uint minScore)
    {
        var insns = index.Insns(f);
        if (context.Count == 0 || insns.Length == 0)
        {
            return BadAddr;
        }

        int valid = context.Count(v => v != Config.MidContextNone);
        if (valid < minScore)
        {
            return BadAddr;
        }

        ulong best = BadAddr;
        uint bestScore = 0;
        for (int center = 0; center < insns.Length; center++)
        {
            uint score = MidContextScore(insns, context, radius, center);
            if (score > bestScore)
            {
                bestScore = score;
                best = f.Start + insns[center].Delta;
            }
        }

        return bestScore < minScore ? BadAddr : best;
    }

    public static uint MidContextScoreAt(GlobalIndex index, FunctionInfo f, IReadOnlyList<ushort> context, uint radius, uint delta)
    {
        var insns = index.Insns(f);
        int center = IndexOfInsn(insns, delta);
        return center < 0 ? 0 : MidContextScore(insns, context, radius, center);
    }

    private static uint MidContextScore(ReadOnlySpan<InsnRecord> insns, IReadOnlyList<ushort> context, uint radius, int center)
    {
        uint score = 0;
        for (int i = 0; i < context.Count; i++)
        {
            if (context[i] == Config.MidContextNone)
            {
                continue;
            }

            int idx = center - (int)radius + i;
            if (idx >= 0 && idx < insns.Length && insns[idx].Itype == context[i])
            {
                score++;
            }
        }

        return score;
    }

    private static int IndexOfInsn(ReadOnlySpan<InsnRecord> insns, uint delta)
    {
        int lo = 0;
        int hi = insns.Length - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            uint d = insns[mid].Delta;
            if (d == delta)
            {
                return mid;
            }

            if (d < delta)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return -1;
    }

    private sealed class Pattern
    {
        private readonly byte[] _bytes;
        private readonly bool[] _mask;
        private readonly byte[] _anchor;
        private readonly int _anchorAt;

        public Pattern(Signature sig)
        {
            _bytes = [.. sig.Bytes];
            _mask = [.. sig.Mask];

            int bestStart = 0;
            int bestLen = 0;
            for (int i = 0; i < _mask.Length;)
            {
                if (!_mask[i])
                {
                    i++;
                    continue;
                }

                int s = i;
                while (i < _mask.Length && _mask[i])
                {
                    i++;
                }

                if (i - s > bestLen)
                {
                    bestStart = s;
                    bestLen = i - s;
                }
            }

            _anchorAt = bestStart;
            _anchor = _bytes.AsSpan(bestStart, bestLen).ToArray();
        }

        public int Next(byte[] data, int from, ulong baseEa, ulong ignoreEa)
        {
            int len = _bytes.Length;
            if (_anchor.Length == 0)
            {
                for (int i = from; i + len <= data.Length; i++)
                {
                    if (baseEa + (ulong)i != ignoreEa)
                    {
                        return i;
                    }
                }

                return -1;
            }

            int pos = from + _anchorAt;
            while (pos + _anchor.Length <= data.Length)
            {
                int rel = data.AsSpan(pos).IndexOf(_anchor);
                if (rel < 0)
                {
                    return -1;
                }

                int at = pos + rel;
                int start = at - _anchorAt;
                pos = at + 1;
                if (start + len > data.Length)
                {
                    return -1;
                }

                if (baseEa + (ulong)start != ignoreEa && Matches(data, start))
                {
                    return start;
                }
            }

            return -1;
        }

        private bool Matches(byte[] data, int start)
        {
            for (int j = 0; j < _bytes.Length; j++)
            {
                if (_mask[j] && data[start + j] != _bytes[j])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
