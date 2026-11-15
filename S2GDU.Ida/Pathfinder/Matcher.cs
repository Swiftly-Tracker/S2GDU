using System.Collections.Concurrent;
using System.Text;
using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Pathfinder;

public static class Matcher
{
    private static bool IsAuthoritative(ModulePriority p) =>
        p is ModulePriority.Signature or ModulePriority.UniqueStr or ModulePriority.ConVar;

    private static FinderResult DispatchFinder(Anchor anchor, GlobalIndex index) => anchor.Priority switch
    {
        ModulePriority.Signature => SignatureFinder.FindBySignature(anchor, index),
        ModulePriority.UniqueStr => StringFinder.FindByString(anchor, index),
        ModulePriority.ConVar => ConvarFinder.FindByConvar(anchor, index),
        ModulePriority.Library => LibraryFinder.FindByLibrary(anchor, index),
        ModulePriority.Proximity => ProximityFinder.FindByProximity(anchor, index),
        _ => new FinderResult(Anchor.BadAddr, anchor.Priority, string.Empty),
    };

    private readonly record struct StructuralCheck(uint Confirmed, string Detail);

    private static StructuralCheck VerifyStructural(ulong candidate, IReadOnlyList<Anchor> anchors, List<FinderResult> votedHits, GlobalIndex index)
    {
        uint confirmed = 0;
        string detail = string.Empty;

        var votedTypes = new HashSet<ModulePriority>();
        foreach (var fr in votedHits)
        {
            votedTypes.Add(fr.Source);
        }

        if (!votedTypes.Contains(ModulePriority.VTable) && index.FuncToVTables.TryGetValue(candidate, out var ft))
        {
            foreach (var anchor in anchors)
            {
                if (anchor.Priority != ModulePriority.VTable || anchor.Name.Length == 0)
                {
                    continue;
                }

                foreach (var (vtname, slot) in ft)
                {
                    if (!index.VTables.TryGetValue(vtname, out var vtinfo))
                    {
                        continue;
                    }

                    string normDem = vtinfo.Demangled.Length > 0 ? RttiNames.NormalizeVTableName(vtinfo.Demangled) : string.Empty;
                    bool nameMatch = (normDem.Length > 0 && normDem == anchor.Name) || vtname == anchor.Name;
                    if (nameMatch)
                    {
                        confirmed++;
                        string piece = $"VTABLE_OK[{anchor.Name}:{anchor.Index}->{slot}]";
                        detail = detail.Length > 0 ? detail + "+" + piece : piece;
                        break;
                    }
                }
            }
        }

        if (!votedTypes.Contains(ModulePriority.DataPtr))
        {
            bool hasDataPtrAnchor = false;
            foreach (var anchor in anchors)
            {
                if (anchor.Priority == ModulePriority.DataPtr)
                {
                    hasDataPtrAnchor = true;
                    break;
                }
            }

            if (hasDataPtrAnchor)
            {
                foreach (var (_, funcEa) in index.DataFuncPtrs)
                {
                    if (funcEa == candidate)
                    {
                        confirmed++;
                        detail = detail.Length > 0 ? detail + "+DATAPTR_OK" : "DATAPTR_OK";
                        break;
                    }
                }
            }
        }

        if (!votedTypes.Contains(ModulePriority.UniqueStr) && index.FuncToStrings.TryGetValue(candidate, out var strs))
        {
            bool foundString = false;
            foreach (var anchor in anchors)
            {
                if (anchor.Priority != ModulePriority.UniqueStr || anchor.Name.Length == 0)
                {
                    continue;
                }

                foreach (string s in strs)
                {
                    if (s == anchor.Name)
                    {
                        foundString = true;
                        break;
                    }
                }

                if (foundString)
                {
                    confirmed++;
                    detail = detail.Length > 0 ? detail + "+STRING_OK" : "STRING_OK";
                    break;
                }
            }
        }

        return new StructuralCheck(confirmed, detail);
    }

    private static MatchResult MatchOne(GlobalIndex index, TrackedFunc tf, ConcurrentDictionary<ulong, ValidationResult> cache, List<FinderResult>? extraHits)
    {
        var hits = new List<FinderResult>();

        foreach (var anchor in tf.Anchors)
        {
            switch (anchor.Priority)
            {
                case ModulePriority.Relational:
                    foreach (var fr in RelationalFinder.FindByRelationalAll(anchor, index))
                    {
                        if (fr.Candidate != Anchor.BadAddr)
                        {
                            hits.Add(fr);
                        }
                    }

                    break;
                case ModulePriority.VTable:
                    foreach (var fr in VTableFinder.FindByVTableAll(anchor, index))
                    {
                        if (fr.Candidate != Anchor.BadAddr)
                        {
                            hits.Add(fr);
                        }
                    }

                    break;
                case ModulePriority.CallChain:
                    foreach (var fr in CallChainFinder.FindByCallChainAll(anchor, index))
                    {
                        if (fr.Candidate != Anchor.BadAddr)
                        {
                            hits.Add(fr);
                        }
                    }

                    break;
                case ModulePriority.Xref:
                    foreach (var fr in XrefFinder.FindByXrefAll(anchor, index))
                    {
                        if (fr.Candidate != Anchor.BadAddr)
                        {
                            hits.Add(fr);
                        }
                    }

                    break;
                case ModulePriority.DataPtr:
                    foreach (var fr in DataPtrFinder.FindByDataPtrAll(anchor, index))
                    {
                        if (fr.Candidate != Anchor.BadAddr)
                        {
                            hits.Add(fr);
                        }
                    }

                    break;
                default:
                    var dr = DispatchFinder(anchor, index);
                    if (dr.Candidate != Anchor.BadAddr)
                    {
                        hits.Add(dr);
                    }

                    break;
            }
        }

        if (extraHits != null)
        {
            foreach (var eh in extraHits)
            {
                if (eh.Candidate != Anchor.BadAddr)
                {
                    hits.Add(eh);
                }
            }
        }

        if (hits.Count == 0)
        {
            return new MatchResult();
        }

        var voteMap = new Dictionary<ulong, List<FinderResult>>();
        var candidateOrder = new List<ulong>();
        foreach (var h in hits)
        {
            if (!voteMap.TryGetValue(h.Candidate, out var list))
            {
                voteMap[h.Candidate] = list = [];
                candidateOrder.Add(h.Candidate);
            }

            list.Add(h);
        }

        var sortedCandidates = candidateOrder.OrderByDescending(ea => voteMap[ea].Count).ToList();

        var expectedVtableClasses = new List<string>();
        foreach (var anchor in tf.Anchors)
        {
            if (anchor.Priority == ModulePriority.VTable && anchor.Name.Length > 0)
            {
                expectedVtableClasses.Add(anchor.Name);
            }
        }

        string? firstFailReason = null;
        var scoredCandidates = new List<(ulong Ea, uint Votes, ValidationResult Vr, float Weighted)>();

        int take = Math.Min(5, sortedCandidates.Count);
        for (int i = 0; i < take; i++)
        {
            ulong ea = sortedCandidates[i];
            var vr = Validator.ValidateCandidate(index, cache, ea, tf.Identity, tf.Reinforcement);

            if (vr.IdentityOk && expectedVtableClasses.Count > 0 && index.FuncToVTables.TryGetValue(ea, out var ft))
            {
                bool classMatch = false;
                foreach (var (vtname, _) in ft)
                {
                    string norm = string.Empty;
                    if (index.VTables.TryGetValue(vtname, out var vtinfo) && vtinfo.Demangled.Length > 0)
                    {
                        norm = RttiNames.NormalizeVTableName(vtinfo.Demangled);
                    }

                    foreach (string expCls in expectedVtableClasses)
                    {
                        if ((norm.Length > 0 && norm == expCls) || vtname == expCls)
                        {
                            classMatch = true;
                            break;
                        }
                    }

                    if (classMatch)
                    {
                        break;
                    }
                }

                if (!classMatch)
                {
                    vr = vr with { IdentityOk = false, FailReason = "wrong_vtable_class" };
                }
            }

            if (i == 0 && !vr.IdentityOk)
            {
                firstFailReason = vr.FailReason;
            }

            if (!vr.IdentityOk)
            {
                continue;
            }

            if (vr.Reinforcement < -0.3f)
            {
                bool hasAuth = false;
                foreach (var fr in voteMap[ea])
                {
                    if (IsAuthoritative(fr.Source))
                    {
                        hasAuth = true;
                        break;
                    }
                }

                if (!hasAuth)
                {
                    if (i == 0)
                    {
                        firstFailReason = "structural_misfit";
                    }

                    continue;
                }
            }

            float multiplier = vr.Reinforcement < 0
                ? (1f + vr.Reinforcement) * (1f + vr.Reinforcement)
                : 1f + (vr.Reinforcement * vr.Reinforcement * 50f);

            uint votes = (uint)voteMap[ea].Count;
            scoredCandidates.Add((ea, votes, vr, votes * multiplier));
        }

        scoredCandidates = scoredCandidates.OrderByDescending(c => c.Weighted).ToList();

        if (scoredCandidates.Count == 0)
        {
            ulong top = sortedCandidates[0];
            return new MatchResult
            {
                Verdict = MatchVerdict.None,
                MatchedEa = top,
                Votes = (uint)voteMap[top].Count,
                Method = firstFailReason != null ? $"IDENTITY_FAIL({firstFailReason})" : "IDENTITY_FAIL",
            };
        }

        var best = scoredCandidates[0];
        ulong bestCandidate = best.Ea;
        uint bestVotes = best.Votes;
        var bestHits = voteMap[bestCandidate];
        var bestVr = best.Vr;

        var result = new MatchResult
        {
            IdentityPassed = true,
            ReinforcementScore = bestVr.Reinforcement,
            MatchedEa = bestCandidate,
            Votes = bestVotes,
        };

        bool hasAuthoritative = false;
        var methodCounts = new List<(string Name, int Count)>();
        foreach (var fr in bestHits)
        {
            if (IsAuthoritative(fr.Source))
            {
                hasAuthoritative = true;
            }

            string name = Names.Of(fr.Source);
            int idx = methodCounts.FindIndex(mc => mc.Name == name);
            if (idx >= 0)
            {
                methodCounts[idx] = (name, methodCounts[idx].Count + 1);
            }
            else
            {
                methodCounts.Add((name, 1));
            }
        }

        var methodSb = new StringBuilder();
        foreach (var (name, count) in methodCounts)
        {
            if (methodSb.Length > 0)
            {
                methodSb.Append('+');
            }

            methodSb.Append(name);
            if (count > 1)
            {
                methodSb.Append('x').Append(count);
            }
        }

        result.Method = methodSb.ToString();

        MatchVerdict verdict;
        if (hasAuthoritative || bestVotes >= Config.MinAnyVotes)
        {
            verdict = MatchVerdict.Match;
        }
        else if (bestVotes >= Config.MinConsensusVotes)
        {
            bool strong = false;
            foreach (var fr in bestHits)
            {
                if (fr.Source != ModulePriority.Library && fr.Source != ModulePriority.Proximity)
                {
                    strong = true;
                    break;
                }
            }

            verdict = strong ? MatchVerdict.Match : MatchVerdict.Ambiguous;
        }
        else
        {
            verdict = MatchVerdict.Ambiguous;
        }

        if (verdict == MatchVerdict.Match && !hasAuthoritative && scoredCandidates.Count > 1
            && scoredCandidates[1].Weighted >= scoredCandidates[0].Weighted * 0.85f)
        {
            verdict = MatchVerdict.Ambiguous;
            result.Method += "(WEIGHT_TIE)";
        }

        var sc = VerifyStructural(bestCandidate, tf.Anchors, bestHits, index);
        result.Structural = sc.Confirmed;
        if (sc.Confirmed > 0)
        {
            result.Method += "+" + sc.Detail;
            if (verdict == MatchVerdict.Ambiguous)
            {
                verdict = MatchVerdict.Match;
            }
        }

        result.Verdict = verdict;
        return result;
    }

    public static MatchResult MatchFunction(GlobalIndex index, TrackedFunc func) =>
        MatchOne(index, func, new ConcurrentDictionary<ulong, ValidationResult>(), null);

    public static MatchResult[] MatchAll(GlobalIndex index, IReadOnlyList<TrackedFunc> funcs, Action<string>? log = null)
    {
        var cache = new ConcurrentDictionary<ulong, ValidationResult>();

        int matched = 0;
        int ambiguous = 0;
        int none = 0;
        var matchIndices = new List<int>();
        for (int i = 0; i < funcs.Count; i++)
        {
            if (funcs[i].Match.Verdict == MatchVerdict.Match)
            {
                matched++;
            }
            else
            {
                matchIndices.Add(i);
            }
        }

        if (matchIndices.Count == 0)
        {
            log?.Invoke("All survived");
            return funcs.Select(f => f.Match).ToArray();
        }

        log?.Invoke($"Pass 1: Parallel Matching ({matchIndices.Count} functions)");

        Parallel.For(0, matchIndices.Count, k =>
        {
            int idx = matchIndices[k];
            var mr = MatchOne(index, funcs[idx], cache, null);
            funcs[idx].Match = mr;
            if (mr.Verdict == MatchVerdict.Match)
            {
                Interlocked.Increment(ref matched);
            }
            else if (mr.Verdict == MatchVerdict.Ambiguous)
            {
                Interlocked.Increment(ref ambiguous);
            }
            else
            {
                Interlocked.Increment(ref none);
            }
        });

        foreach (int idx in matchIndices)
        {
            var tf = funcs[idx];
            if (tf.Match.Verdict == MatchVerdict.Match)
            {
                log?.Invoke($"MATCH {tf.Name} -> 0x{tf.Match.MatchedEa:X}");
            }
            else if (tf.Match.Verdict == MatchVerdict.Ambiguous)
            {
                log?.Invoke($"AMBIGUOUS {tf.Name}");
            }
            else
            {
                log?.Invoke($"NO MATCH {tf.Name}");
            }
        }

        if (matched >= 3 && (none > 0 || ambiguous > 0))
        {
            long dpDelta = DataPtrFinder.CalibrateDataPtrDelta(index, funcs);
            var matchedMap = new Dictionary<ulong, ulong>();
            foreach (var tf in funcs)
            {
                if (tf.Match.Verdict == MatchVerdict.Match)
                {
                    matchedMap[tf.OriginalEa] = tf.Match.MatchedEa;
                }
            }

            var p2Indices = new List<int>();
            for (int i = 0; i < funcs.Count; i++)
            {
                if (funcs[i].Match.Verdict != MatchVerdict.Match)
                {
                    p2Indices.Add(i);
                }
            }

            log?.Invoke($"Pass 2: Parallel Retry ({p2Indices.Count} functions)");

            Parallel.For(0, p2Indices.Count, k =>
            {
                int idx = p2Indices[k];
                var extra = new List<FinderResult>();

                if (dpDelta != 0)
                {
                    foreach (var a in funcs[idx].Anchors)
                    {
                        if (a.Priority != ModulePriority.DataPtr)
                        {
                            continue;
                        }

                        int added = 0;
                        foreach (var fr in DataPtrFinder.FindByDataPtrCalibratedAll(a, index, dpDelta))
                        {
                            if (++added > Config.DataPtrCalMaxCandidates)
                            {
                                break;
                            }

                            extra.Add(fr);
                        }
                    }
                }

                foreach (var a in funcs[idx].Anchors)
                {
                    if (a.Priority != ModulePriority.Relational)
                    {
                        continue;
                    }

                    extra.AddRange(RelationalFinder.FindByRelationalMatchedAll(a, index, matchedMap));
                }

                var mr = MatchOne(index, funcs[idx], cache, extra);
                if (mr.Verdict == MatchVerdict.Match)
                {
                    mr.Method = "PASS2+" + mr.Method;
                    funcs[idx].Match = mr;
                    Interlocked.Increment(ref matched);
                }
            });

            foreach (int idx in p2Indices)
            {
                if (funcs[idx].Match.Verdict == MatchVerdict.Match)
                {
                    log?.Invoke($"RESCUED {funcs[idx].Name}");
                }
            }
        }

        return funcs.Select(f => f.Match).ToArray();
    }
}
