using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Crawler;

internal readonly record struct LandmarkInfo(string Name, byte Type)
{
    public static readonly LandmarkInfo None = new(string.Empty, 0);
}

internal static class CallChainModule
{
    private const ulong BadAddr = ulong.MaxValue;

    public static LandmarkInfo DetectLandmark(ulong fea, GlobalIndex index)
    {
        if (index.FuncToStrings.TryGetValue(fea, out var strs))
        {
            foreach (string s in strs)
            {
                if (s.Length < Config.MinStringLength)
                {
                    continue;
                }

                if (index.StringToFuncs.TryGetValue(s, out var refs) && refs.Count == 1)
                {
                    return new LandmarkInfo(s, 0);
                }
            }
        }

        if (index.FuncToVTables.TryGetValue(fea, out var vtRefs) && vtRefs.Count > 0)
        {
            var (vtname, slot) = vtRefs[0];
            if (index.VTables.TryGetValue(vtname, out var vt))
            {
                string rawName = vt.Demangled.Length > 0 ? vt.Demangled : vtname;
                rawName = RttiNames.NormalizeVTableName(rawName);
                return new LandmarkInfo($"{rawName}[{slot}]", 1);
            }
        }

        if (strs != null)
        {
            foreach (string s in strs)
            {
                if (IndexBuilder.IsConvarString(s))
                {
                    return new LandmarkInfo(s, 2);
                }
            }
        }

        if (index.FuncToDataSegPtrs.TryGetValue(fea, out var ptrs) && ptrs.Count > 0)
        {
            ulong ptrEa = ptrs[0];
            ulong rva = ptrEa - index.ImageBase;
            uint lmSize = index.FuncByStart(fea)?.Size ?? 0;
            return new LandmarkInfo($"0x{rva:X}:{lmSize}", 3);
        }

        return LandmarkInfo.None;
    }

    private readonly record struct BfsNode(ulong FuncEa, byte Depth, byte Directions);

    public static List<Anchor> Collect(ulong fea, GlobalIndex index)
    {
        var anchors = new List<Anchor>();

        uint trackedSize = index.FuncByStart(fea)?.Size ?? 0;

        var queue = new Queue<BfsNode>();
        var visited = new HashSet<ulong> { fea };

        if (index.Callers.TryGetValue(fea, out var callers))
        {
            foreach (ulong caller in callers)
            {
                if (visited.Add(caller))
                {
                    queue.Enqueue(new BfsNode(caller, 1, 0));
                }
            }
        }

        if (index.Callees.TryGetValue(fea, out var callees))
        {
            foreach (ulong callee in callees)
            {
                if (visited.Add(callee))
                {
                    queue.Enqueue(new BfsNode(callee, 1, 1));
                }
            }
        }

        while (queue.Count > 0 && anchors.Count < Config.CallChainMaxAnchors)
        {
            if (visited.Count > Config.CallChainMaxVisit)
            {
                break;
            }

            var node = queue.Dequeue();

            var lm = DetectLandmark(node.FuncEa, index);
            if (lm.Name.Length > 0)
            {
                anchors.Add(new Anchor
                {
                    Priority = ModulePriority.CallChain,
                    Name = lm.Name,
                    ChainDepth = node.Depth,
                    ChainDirections = node.Directions,
                    ChainLandmarkType = lm.Type,
                    Fanout = index.Fanout(node.FuncEa),
                    FuncSize = trackedSize,
                    ResolvedEa = node.FuncEa,
                });

                continue;
            }

            if (node.Depth >= Config.CallChainMaxDepth)
            {
                continue;
            }

            uint fanout = index.Fanout(node.FuncEa);
            if (fanout > Config.MaxRelationalFanout * 2)
            {
                continue;
            }

            if (index.Callers.TryGetValue(node.FuncEa, out var nCallers))
            {
                foreach (ulong caller in nCallers)
                {
                    if (visited.Count > Config.CallChainMaxVisit)
                    {
                        break;
                    }

                    if (visited.Add(caller))
                    {
                        queue.Enqueue(new BfsNode(caller, (byte)(node.Depth + 1), node.Directions));
                    }
                }
            }

            if (index.Callees.TryGetValue(node.FuncEa, out var nCallees))
            {
                foreach (ulong callee in nCallees)
                {
                    if (visited.Count > Config.CallChainMaxVisit)
                    {
                        break;
                    }

                    if (visited.Add(callee))
                    {
                        byte newDirs = (byte)(node.Directions | (1 << node.Depth));
                        queue.Enqueue(new BfsNode(callee, (byte)(node.Depth + 1), newDirs));
                    }
                }
            }
        }

        anchors.Sort((a, b) =>
        {
            if (a.ChainDepth != b.ChainDepth)
            {
                return a.ChainDepth.CompareTo(b.ChainDepth);
            }

            return a.ChainLandmarkType.CompareTo(b.ChainLandmarkType);
        });

        if (anchors.Count > Config.CallChainMaxAnchors)
        {
            anchors.RemoveRange((int)Config.CallChainMaxAnchors, anchors.Count - (int)Config.CallChainMaxAnchors);
        }

        return anchors;
    }
}
