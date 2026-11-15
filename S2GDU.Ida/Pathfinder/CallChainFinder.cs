using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Pathfinder;

internal static class CallChainFinder
{
    public static ulong FindLandmarkEa(Anchor anchor, GlobalIndex index)
    {
        switch (anchor.ChainLandmarkType)
        {
            case 0:
                if (index.StringToFuncs.TryGetValue(anchor.Name, out var funcs) && funcs.Count > 0 && funcs.Count <= 5)
                {
                    return funcs[0];
                }

                break;

            case 1:
            {
                int bracket = anchor.Name.IndexOf('[');
                if (bracket < 0)
                {
                    break;
                }

                string className = anchor.Name[..bracket];
                string slotStr = anchor.Name[(bracket + 1)..].TrimEnd(']');
                if (!uint.TryParse(slotStr, out uint slot))
                {
                    break;
                }

                foreach (var (vtname, vt) in index.VTables)
                {
                    string normDem = vt.Demangled.Length > 0 ? RttiNames.NormalizeVTableName(vt.Demangled) : string.Empty;
                    bool match = (normDem.Length > 0 && normDem == className) || vtname == className;
                    if (!match)
                    {
                        continue;
                    }

                    if (slot < vt.Slots.Count)
                    {
                        var f = index.FuncAt(vt.Slots[(int)slot]);
                        if (f != null)
                        {
                            return f.Start;
                        }
                    }

                    break;
                }

                break;
            }

            case 2:
                if (index.ConvarNameToFuncs.TryGetValue(anchor.Name, out var cvFuncs) && cvFuncs.Count > 0)
                {
                    return cvFuncs[0];
                }

                break;

            case 3:
            {
                int colonIdx = anchor.Name.IndexOf(':');
                string rvaPart = colonIdx >= 0 ? anchor.Name[..colonIdx] : anchor.Name;
                string hexPart = rvaPart.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? rvaPart[2..] : rvaPart;
                if (!ulong.TryParse(hexPart, System.Globalization.NumberStyles.HexNumber, null, out ulong oldRva))
                {
                    break;
                }

                uint lmSize = 0;
                if (colonIdx >= 0)
                {
                    uint.TryParse(anchor.Name[(colonIdx + 1)..], out lmSize);
                }

                ulong approxEa = index.ImageBase + oldRva;
                ulong bestFunc = Anchor.BadAddr;
                long bestDist = long.MaxValue;

                foreach (var (ptrEa, funcEa) in index.DataFuncPtrs)
                {
                    var seg = index.SegmentAt(ptrEa);
                    if (seg == null || !seg.Name.Contains(".data", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (lmSize > 0)
                    {
                        var cf = index.FuncByStart(funcEa);
                        if (cf != null)
                        {
                            uint cs = cf.Size;
                            if (cs < lmSize / 4 || cs > lmSize * 4)
                            {
                                continue;
                            }
                        }
                    }

                    long dist = Math.Abs((long)ptrEa - (long)approxEa);
                    if (dist < bestDist)
                    {
                        bestDist = dist;
                        bestFunc = funcEa;
                    }
                }

                if (bestFunc != Anchor.BadAddr && bestDist < Config.DataPtrSectionTolerance)
                {
                    return bestFunc;
                }

                break;
            }
        }

        return Anchor.BadAddr;
    }

    private static bool SizeOk(GlobalIndex index, Anchor anchor, ulong candidateEa)
    {
        if (anchor.FuncSize == 0)
        {
            return true;
        }

        var cf = index.FuncByStart(candidateEa);
        if (cf == null)
        {
            return false;
        }

        uint candSize = cf.Size;
        uint orig = anchor.FuncSize;
        uint factor = orig < 64 ? 4u : 2u;
        uint lo = orig / (factor + 1);
        uint hi = orig * (factor + 1);
        return candSize >= lo && candSize <= hi;
    }

    public static List<FinderResult> FindByCallChainAll(Anchor anchor, GlobalIndex index)
    {
        var results = new List<FinderResult>();

        if (anchor.ChainDepth == 0 || anchor.Name.Length == 0)
        {
            return results;
        }

        ulong landmarkEa = FindLandmarkEa(anchor, index);
        if (landmarkEa == Anchor.BadAddr)
        {
            return results;
        }

        var currentSet = new HashSet<ulong> { landmarkEa };

        for (int hop = anchor.ChainDepth - 1; hop >= 0; hop--)
        {
            if (currentSet.Count == 0)
            {
                break;
            }

            bool originalWasCallee = ((anchor.ChainDirections >> hop) & 1) != 0;

            var nextSet = new HashSet<ulong>();
            foreach (ulong ea in currentSet)
            {
                if (originalWasCallee)
                {
                    if (index.Callers.TryGetValue(ea, out var callers))
                    {
                        foreach (ulong caller in callers)
                        {
                            nextSet.Add(caller);
                        }
                    }
                }
                else
                {
                    if (index.Callees.TryGetValue(ea, out var callees))
                    {
                        foreach (ulong callee in callees)
                        {
                            nextSet.Add(callee);
                        }
                    }
                }
            }

            currentSet = nextSet;
            if (currentSet.Count > 200)
            {
                break;
            }
        }

        string lmType = anchor.ChainLandmarkType switch { 0 => "str", 1 => "vt", 2 => "cv", _ => "dp" };

        foreach (ulong candidate in currentSet)
        {
            var f = index.FuncByStart(candidate);
            if (f == null || index.LibraryFuncs.Contains(f.Start))
            {
                continue;
            }

            if (!SizeOk(index, anchor, f.Start))
            {
                continue;
            }

            results.Add(new FinderResult(f.Start, ModulePriority.CallChain,
                $"callchain({anchor.ChainLandmarkType},{lmType},d={anchor.ChainDepth}): {anchor.Name}"));
        }

        return results;
    }
}
