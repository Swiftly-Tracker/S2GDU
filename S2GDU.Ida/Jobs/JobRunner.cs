using System.Collections.Concurrent;
using System.Globalization;
using S2GDU.Ida.Crawler;
using S2GDU.Ida.Gamedata;
using S2GDU.Ida.Index;
using S2GDU.Ida.Model;
using S2GDU.Ida.Pathfinder;
using S2GDU.Ida.Signatures;
using S2GDU.Ida.Storage;
using GD = S2GDU.Ida.Gamedata.Gamedata;

namespace S2GDU.Ida.Jobs;

public static class JobRunner
{
    private const ulong BadAddr = Anchor.BadAddr;
    private const int SameFuncScanLimit = 4096;

    public static JobResult Run(JobRequest request, Action<string> stage)
    {
        stage("index");
        var index = IndexBuilder.Build(stage);

        return request.Command switch
        {
            JobCommand.Import => Import(index, request, stage),
            JobCommand.Track => Track(index, request),
            JobCommand.Backtrack => Backtrack(index, request, stage),
            JobCommand.Gensig => Gensig(index, request),
            _ => throw new ArgumentOutOfRangeException(nameof(request), request.Command, null),
        };
    }

    private static JobResult Import(GlobalIndex index, JobRequest request, Action<string> stage)
    {
        string seed = request.Seed ?? throw new ArgumentException("import requires a seed gamedata file.");
        string output = request.Output ?? throw new ArgumentException("import requires an output path.");

        string library = GD.LibraryName(index.BinaryName);
        var entries = GD.ReadSeed(seed, index.IsLinux)
            .Where(e => e.Library.Length == 0 || string.Equals(e.Library, library, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var result = new JobResult { Total = entries.Count };

        stage("import:resolve");
        var resolved = new (ulong Target, FunctionInfo? Func, string? Note, string VtClass)[entries.Count];
        Parallel.For(0, entries.Count, i => resolved[i] = Resolve(index, entries[i]));

        var names = new HashSet<string>(StringComparer.Ordinal);
        var sigTargets = new HashSet<ulong>();
        var vtSlots = new HashSet<(string, int)>();
        var accepted = new List<int>();

        foreach (bool vtablePass in new[] { false, true })
        {
            for (int i = 0; i < entries.Count; i++)
            {
                var e = entries[i];
                if (e.Offset >= 0 != vtablePass)
                {
                    continue;
                }

                var r = resolved[i];
                if (r.Func == null)
                {
                    result.Lines.Add($"{e.Name,-52}  SKIP ({r.Note})");
                    continue;
                }

                bool field = IsField(e.Name);
                bool duplicate = names.Contains(e.Name) ||
                                 (!vtablePass && sigTargets.Contains(r.Target)) ||
                                 (vtablePass && !field && vtSlots.Contains((r.VtClass, e.Offset)));
                if (duplicate)
                {
                    result.Lines.Add($"{e.Name,-52}  SKIP (duplicate)");
                    continue;
                }

                names.Add(e.Name);
                if (vtablePass && !field)
                {
                    vtSlots.Add((r.VtClass, e.Offset));
                }
                else if (!vtablePass)
                {
                    sigTargets.Add(r.Target);
                }

                if (r.Note != null)
                {
                    result.Lines.Add($"{e.Name,-52}  WARN ({r.Note})");
                }

                accepted.Add(i);
            }
        }

        stage("import:crawl");
        var tracked = new TrackedFunc[accepted.Count];
        Parallel.For(0, accepted.Count, k =>
        {
            int i = accepted[k];
            var e = entries[i];
            var r = resolved[i];
            var f = r.Func!;
            bool field = IsField(e.Name);
            bool vtable = e.Offset >= 0 && !field;
            var tf = MakeTracked(index, f, e.Name, field ? "GAMEDATA_FIELD" : vtable ? "GAMEDATA_VTABLE" : "GAMEDATA_IMPORT");

            if (field)
            {
                tf.FieldOffset = e.Offset;
                tf.MidContext = SigGen.CollectMidContext(index, f, r.Target, Config.MidContextRadius);
            }
            else if (vtable)
            {
                tf.VTableClass = r.VtClass;
                tf.VTableOffset = e.Offset;
            }
            else if (r.Target != f.Start)
            {
                tf.SigOffset = (int)(r.Target - f.Start);
                tf.ExportSig = SigGen.Make(index, r.Target, r.Target, 0);
                tf.MidContext = SigGen.CollectMidContext(index, f, r.Target, Config.MidContextRadius);
            }

            tracked[k] = tf;
        });

        foreach (var tf in tracked)
        {
            string where = tf.FieldOffset >= 0 ? $"field +{tf.FieldOffset}" : tf.VTableOffset >= 0 ? $"{tf.VTableClass}[{tf.VTableOffset}]" : tf.SigOffset > 0 ? $"+{tf.SigOffset}" : "start";
            result.Lines.Add($"{tf.Name,-52}  OK 0x{tf.OriginalEa:X} {where} ({tf.Anchors.Count} anchors)");
        }

        ClueFileStore.Write(output, new ClueFile(index.BinaryName, [.. tracked]));
        result.Matched = tracked.Length;
        result.None = entries.Count - tracked.Length;
        result.Output = output;
        return result;
    }

    private static (ulong Target, FunctionInfo? Func, string? Note, string VtClass) Resolve(GlobalIndex index, SeedEntry e)
    {
        if (e.Offset >= 0)
        {
            if (IsField(e.Name))
            {
                return ResolveField(index, e);
            }

            string cls = ResolveVTableClass(e.Name, index);
            if (cls.Length == 0)
            {
                return (BadAddr, null, "no vtable class", cls);
            }

            if (!index.VTables.TryGetValue(index.ClassToVtName[cls], out var vt) || e.Offset >= vt.Slots.Count)
            {
                return (BadAddr, null, $"{cls}[{e.Offset}] not found", cls);
            }

            var vf = index.FuncAt(vt.Slots[e.Offset]);
            return vf == null ? (BadAddr, null, $"{cls}[{e.Offset}] not in func", cls) : (vf.Start, vf, null, cls);
        }

        var sig = GD.ParseSig(e.Sig);
        if (sig.IsEmpty)
        {
            return (BadAddr, null, "bad signature", string.Empty);
        }

        var hits = SigGen.FindAll(index, sig, SameFuncScanLimit);
        if (hits.Count == 0)
        {
            return (BadAddr, null, "no match", string.Empty);
        }

        var f = index.FuncAt(hits[0]);
        string? note = null;
        if (hits.Count > 1)
        {
            bool sameFunc = f != null && hits.Count < SameFuncScanLimit && hits.All(h => index.FuncAt(h) == f);
            if (!sameFunc)
            {
                if (hits.Count > 2)
                {
                    return (BadAddr, null, "not unique: 3+ matches", string.Empty);
                }

                var f2 = index.FuncAt(hits[1]);
                note = $"2 matches: {f?.Name ?? "?"} vs {f2?.Name ?? "?"}, using first";
            }
        }

        return f == null ? (BadAddr, null, "not in func", string.Empty) : (hits[0], f, note, string.Empty);
    }

    private static bool IsField(string name) => name.Contains("::m_", StringComparison.Ordinal);

    private static (ulong Target, FunctionInfo? Func, string? Note, string VtClass) ResolveField(GlobalIndex index, SeedEntry e)
    {
        string cls = e.Name[..e.Name.IndexOf("::", StringComparison.Ordinal)];
        if (!index.ClassToVtName.TryGetValue(cls, out string? vtName) || !index.VTables.TryGetValue(vtName, out var vt))
        {
            return (BadAddr, null, $"no vtable for {cls}", cls);
        }

        var methods = vt.Slots.Select(index.FuncAt).OfType<FunctionInfo>().ToHashSet();
        ulong slotStart = vt.StartEa + (vtName.StartsWith("_ZTV", StringComparison.Ordinal) ? (ulong)(2 * index.PointerSize) : 0);
        var ctors = new[] { vt.StartEa, slotStart }.Distinct()
            .SelectMany(ea => index.DataRefToFuncs.TryGetValue(ea, out var l) ? l : [])
            .Select(index.FuncAt).OfType<FunctionInfo>();

        var roots = methods.Concat(ctors).DistinctBy(f => f.Start).ToList();
        var layer = roots;
        var seen = roots.Select(f => f.Start).ToHashSet();
        for (int depth = 0; depth <= FieldCalleeDepth && layer.Count > 0; depth++)
        {
            var best = layer
                .Select(f => (Func: f, Hit: Array.FindIndex(f.ThisFields, a => a.Disp == e.Offset)))
                .Where(c => c.Hit >= 0)
                .OrderBy(c => c.Func.ThisFields.All(a => a.Disp == e.Offset) ? 0 : 1)
                .ThenBy(c => methods.Contains(c.Func) ? 0 : 1)
                .ThenBy(c => c.Func.InsnCount)
                .FirstOrDefault();
            if (best.Func != null)
            {
                return (best.Func.Start + best.Func.ThisFields[best.Hit].Delta, best.Func, null, cls);
            }

            layer = [.. layer
                .SelectMany(f => f.ThisCalls)
                .Where(seen.Add)
                .Select(index.FuncByStart)
                .OfType<FunctionInfo>()];
        }

        if (e.Offset >= 128)
        {
            var foreign = index.Functions
                .Select(f => (Func: f, Hit: Array.FindIndex(f.OtherFields, a => a.Disp == e.Offset)))
                .Where(c => c.Hit >= 0)
                .OrderBy(c => c.Func.InsnCount)
                .Take(FieldForeignMax + 1)
                .ToList();
            if (foreign.Count is > 0 and <= FieldForeignMax)
            {
                var pick = foreign[0];
                return (pick.Func.Start + pick.Func.OtherFields[pick.Hit].Delta, pick.Func, null, cls);
            }
        }

        return (BadAddr, null, $"{cls}+{e.Offset} not accessed through this", cls);
    }

    private const int FieldCalleeDepth = 2;
    private const int FieldForeignMax = 4;

    private static string? UpdateFieldOffset(GlobalIndex index, TrackedFunc tf)
    {
        var f = index.FuncAt(tf.Match.MatchedEa);
        FieldAccess[] acc = f == null ? [] : [.. f.ThisFields, .. f.OtherFields];
        int pick = -1;
        if (acc.Length > 0 && acc.All(a => a.Disp == acc[0].Disp))
        {
            pick = 0;
        }
        else if (f != null)
        {
            uint best = 0;
            bool clash = false;
            for (int k = 0; k < acc.Length; k++)
            {
                uint score = SigGen.MidContextScoreAt(index, f, tf.MidContext, Config.MidContextRadius, acc[k].Delta);
                if (score > best)
                {
                    best = score;
                    pick = k;
                    clash = false;
                }
                else if (score == best && pick >= 0 && acc[k].Disp != acc[pick].Disp)
                {
                    clash = true;
                }
            }

            uint need = Math.Min(Config.MidContextMinScore, (uint)tf.MidContext.Count(v => v != Config.MidContextNone));
            if (clash || best < need)
            {
                pick = -1;
            }
        }

        if (pick < 0)
        {
            tf.Match.Verdict = MatchVerdict.Ambiguous;
            tf.Match.Method += "+FIELD_LOST";
            return $"+{tf.FieldOffset} not re-derived";
        }

        tf.MidContext = SigGen.CollectMidContext(index, f!, f!.Start + acc[pick].Delta, Config.MidContextRadius);
        int old = tf.FieldOffset;
        tf.FieldOffset = acc[pick].Disp;
        return old == tf.FieldOffset ? null : $"[+{old} -> +{tf.FieldOffset}] CHANGED (field)";
    }

    private static string ResolveVTableClass(string name, GlobalIndex index)
    {
        int sep = name.IndexOf("::", StringComparison.Ordinal);
        if (sep >= 0 && index.ClassToVtName.ContainsKey(name[..sep]))
        {
            return name[..sep];
        }

        int u = name.LastIndexOf('_');
        while (u > 0)
        {
            string candidate = name[..u];
            if (index.ClassToVtName.ContainsKey(candidate))
            {
                return candidate;
            }

            u = name.LastIndexOf('_', u - 1);
        }

        return string.Empty;
    }

    private static TrackedFunc MakeTracked(GlobalIndex index, FunctionInfo f, string name, string method)
    {
        var cr = Crawler.Crawler.Crawl(index, f.Start);
        var tf = new TrackedFunc
        {
            Name = name,
            OriginalEa = f.Start,
            Identity = cr.Identity,
            Reinforcement = cr.Reinforcement,
            Anchors = [.. cr.Anchors],
            Match = new MatchResult
            {
                Verdict = MatchVerdict.Match,
                MatchedEa = f.Start,
                Method = method,
                Votes = 1,
                IdentityPassed = true,
                ReinforcementScore = 1.0f,
            },
        };

        RegenStartSigs(index, tf, f);
        return tf;
    }

    private static void RegenStartSigs(GlobalIndex index, TrackedFunc tf, FunctionInfo f)
    {
        tf.ExportSig = SigGen.Make(index, f.Start, f.Start, 0);
        RegenTrackingSig(index, tf, f, tf.ExportSig);
    }

    private static void RegenTrackingSig(GlobalIndex index, TrackedFunc tf, FunctionInfo f, Signature fallback)
    {
        tf.PrologueLength = SigGen.DetectPrologueLength(index, f.Start);
        tf.TrackingSig = new Signature();
        if (tf.PrologueLength > 0 && f.Size > Config.MinFuncSizeForSkip)
        {
            ulong skip = f.Start + tf.PrologueLength;
            tf.TrackingSig = SigGen.Make(index, skip, skip, tf.PrologueLength);
        }

        if (tf.TrackingSig.IsEmpty)
        {
            tf.TrackingSig = fallback;
        }
    }

    private static JobResult Track(GlobalIndex index, JobRequest request)
    {
        string output = request.Output ?? request.Clue ?? throw new ArgumentException("track requires an output path.");
        var existing = request.Clue != null && File.Exists(request.Clue) ? ClueFileStore.Read(request.Clue).Functions : [];
        var result = new JobResult { Total = request.Targets.Count };

        var seen = existing.Select(t => t.OriginalEa).ToHashSet();
        var picked = new List<(string Name, FunctionInfo Func)>();
        foreach (string target in request.Targets)
        {
            var (ea, name) = ResolveTarget(index, target);
            var f = ea == BadAddr ? null : index.FuncAt(ea);
            if (f == null)
            {
                result.Lines.Add($"{target,-52}  SKIP (not a function)");
                continue;
            }

            if (!seen.Add(f.Start))
            {
                result.Lines.Add($"{target,-52}  SKIP (already tracked)");
                continue;
            }

            picked.Add((name ?? f.Name, f));
        }

        var tracked = new TrackedFunc[picked.Count];
        Parallel.For(0, picked.Count, i => tracked[i] = MakeTracked(index, picked[i].Func, picked[i].Name, "TRACKED"));

        foreach (var tf in tracked)
        {
            result.Lines.Add($"{tf.Name,-52}  OK 0x{tf.OriginalEa:X} ({tf.Anchors.Count} anchors)");
        }

        existing.AddRange(tracked);
        ClueFileStore.Write(output, new ClueFile(index.BinaryName, existing));
        result.Matched = tracked.Length;
        result.None = request.Targets.Count - tracked.Length;
        result.Output = output;
        return result;
    }

    private static (ulong Ea, string? Name) ResolveTarget(GlobalIndex index, string target)
    {
        string t = target.Trim();
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            ulong.TryParse(t.AsSpan(2), NumberStyles.HexNumber, null, out ulong ea))
        {
            return (ea, null);
        }

        foreach (var f in index.Functions)
        {
            if (f.Name == t)
            {
                return (f.Start, t);
            }
        }

        return (BadAddr, null);
    }

    private static JobResult Backtrack(GlobalIndex index, JobRequest request, Action<string> stage)
    {
        string cluePath = request.Clue ?? throw new ArgumentException("backtrack requires a previous clue file.");
        string output = request.Output ?? throw new ArgumentException("backtrack requires an output path.");

        var clue = ClueFileStore.Read(cluePath);
        var funcs = clue.Functions;
        var lines = new ConcurrentBag<(int, string)>();

        stage("backtrack:prevalidate");
        Parallel.For(0, funcs.Count, i =>
        {
            var tf = funcs[i];
            tf.Match = new MatchResult();
            if (tf.VTableOffset >= 0 || tf.TrackingSig.IsEmpty)
            {
                return;
            }

            var hits = SigGen.FindAll(index, tf.TrackingSig, 2);
            var f = hits.Count == 1 ? index.FuncAt(hits[0]) : null;
            if (f == null)
            {
                return;
            }

            tf.Match = new MatchResult
            {
                Verdict = MatchVerdict.Match,
                MatchedEa = f.Start,
                Method = "SURVIVED",
                Votes = 1,
                IdentityPassed = true,
                ReinforcementScore = 1.0f,
            };
        });

        stage("backtrack:match");
        Matcher.MatchAll(index, funcs, stage);

        stage("backtrack:regen");
        Parallel.For(0, funcs.Count, i =>
        {
            var tf = funcs[i];
            if (tf.Match.Verdict != MatchVerdict.Match || tf.Match.MatchedEa == BadAddr || tf.Match.Method == "SURVIVED")
            {
                return;
            }

            var f = index.FuncAt(tf.Match.MatchedEa);
            if (f == null)
            {
                lines.Add((i, $"{tf.Name,-52}  SKIP regen (func lost)"));
                return;
            }

            Regen(index, tf, f);
        });

        stage("backtrack:vtable");
        Parallel.For(0, funcs.Count, i =>
        {
            var tf = funcs[i];
            if (tf.Match.Verdict != MatchVerdict.Match || tf.VTableOffset < 0 || tf.VTableClass.Length == 0 || tf.Match.MatchedEa == BadAddr)
            {
                return;
            }

            string? note = UpdateVTableOffset(index, tf);
            if (note != null)
            {
                lines.Add((i, $"{tf.Name,-52}  {tf.VTableClass} {note}"));
            }
        });

        stage("backtrack:fields");
        Parallel.For(0, funcs.Count, i =>
        {
            var tf = funcs[i];
            if (tf.Match.Verdict != MatchVerdict.Match || tf.FieldOffset < 0 || tf.Match.MatchedEa == BadAddr)
            {
                return;
            }

            string? note = UpdateFieldOffset(index, tf);
            if (note != null)
            {
                lines.Add((i, $"{tf.Name,-52}  {note}"));
            }
        });

        var result = new JobResult { Total = funcs.Count, Output = output };
        foreach (var tf in funcs)
        {
            switch (tf.Match.Verdict)
            {
                case MatchVerdict.Match:
                    result.Matched++;
                    break;
                case MatchVerdict.Ambiguous:
                    result.Ambiguous++;
                    break;
                default:
                    result.None++;
                    break;
            }

            if (tf.Match.Method == "SURVIVED")
            {
                result.Survived++;
            }
            else if (tf.Match.Method.StartsWith("PASS2+", StringComparison.Ordinal) && tf.Match.Verdict == MatchVerdict.Match)
            {
                result.Rescued++;
            }
        }

        for (int i = 0; i < funcs.Count; i++)
        {
            var tf = funcs[i];
            string ea = tf.Match.MatchedEa == BadAddr ? "-" : $"0x{tf.Match.MatchedEa:X}";
            result.Lines.Add($"{tf.Name,-52}  {Names.Of(tf.Match.Verdict),-9} {ea} {tf.Match.Method}");
        }

        result.Lines.AddRange(lines.OrderBy(l => l.Item1).Select(l => l.Item2));
        ClueFileStore.Write(output, new ClueFile(index.BinaryName, funcs));
        return result;
    }

    private static void Regen(GlobalIndex index, TrackedFunc tf, FunctionInfo f)
    {
        if (tf.SigOffset <= 0)
        {
            RegenStartSigs(index, tf, f);
            return;
        }

        ulong target = f.Start + (ulong)tf.SigOffset;
        if (tf.MidContext.Count > 0)
        {
            ulong ctx = SigGen.FindMidContextMatch(index, f, tf.MidContext, Config.MidContextRadius, Config.MidContextMinScore);
            if (ctx != BadAddr && ctx != target)
            {
                target = ctx;
                tf.SigOffset = (int)(ctx - f.Start);
            }
        }

        if (target < f.End)
        {
            tf.ExportSig = SigGen.Make(index, target, target, 0);
            tf.MidContext = SigGen.CollectMidContext(index, f, target, Config.MidContextRadius);
        }
        else
        {
            tf.ExportSig = SigGen.Make(index, f.Start, f.Start, 0);
            tf.SigOffset = 0;
        }

        RegenTrackingSig(index, tf, f, SigGen.Make(index, f.Start, f.Start, 0));
    }

    private static string? UpdateVTableOffset(GlobalIndex index, TrackedFunc tf)
    {
        if (!index.ClassToVtName.TryGetValue(tf.VTableClass, out string? vtName) || !index.VTables.TryGetValue(vtName, out var vt))
        {
            return "class not found in new binary";
        }

        ulong matched = tf.Match.MatchedEa;
        uint size = tf.Reinforcement.Size;
        bool skipEa = false;
        if (size is > 0 and <= 16 && index.FuncAt(matched) is { } mf)
        {
            uint lo = size > 2 ? size - 2 : 1;
            uint hi = size + 2;
            skipEa = mf.Size < lo || mf.Size > hi;
        }

        if (!skipEa)
        {
            if (index.FuncToVTables.TryGetValue(matched, out var refs))
            {
                foreach (var r in refs)
                {
                    if (r.VTable == vtName)
                    {
                        return SetSlot(tf, (int)r.Slot, string.Empty);
                    }
                }
            }

            int old = tf.VTableOffset;
            if (old < vt.Slots.Count && index.FuncAt(vt.Slots[old])?.Start == matched)
            {
                return null;
            }

            for (int s = 0; s < vt.Slots.Count; s++)
            {
                if (index.FuncAt(vt.Slots[s])?.Start == matched)
                {
                    return SetSlot(tf, s, " (direct)");
                }
            }

            for (int s = 0; s < vt.Slots.Count; s++)
            {
                if (index.Callees.TryGetValue(vt.Slots[s], out var callees) && callees.Contains(matched))
                {
                    return SetSlot(tf, s, " (wrapper)");
                }
            }
        }

        int tol = (int)Config.VTableSlotBaseTolerance;
        int oldSlot = tf.VTableOffset;
        int best = -1;
        int bestDist = int.MaxValue;
        FunctionInfo? bestFunc = null;
        for (int s = Math.Max(0, oldSlot - tol); s < Math.Min(vt.Slots.Count, oldSlot + tol + 1); s++)
        {
            var sf = index.FuncAt(vt.Slots[s]);
            if (sf == null)
            {
                continue;
            }

            if (size > 0)
            {
                uint lo = size <= 8 ? (size > 1 ? size - 1 : 1) : size / 3;
                uint hi = size <= 8 ? size + 1 : size * 3;
                if (sf.Size < lo || sf.Size > hi)
                {
                    continue;
                }
            }

            int d = Math.Abs(s - oldSlot);
            if (d < bestDist)
            {
                bestDist = d;
                best = s;
                bestFunc = sf;
            }
        }

        if (bestFunc == null)
        {
            return "matched func not in vtable slots";
        }

        tf.Match.MatchedEa = bestFunc.Start;
        string note = $"[{oldSlot} -> {best}] OVERRIDE (slot)";
        tf.VTableOffset = best;
        return note;
    }

    private static string? SetSlot(TrackedFunc tf, int slot, string how)
    {
        if (slot == tf.VTableOffset)
        {
            return null;
        }

        string note = $"[{tf.VTableOffset} -> {slot}] CHANGED{how}";
        tf.VTableOffset = slot;
        return note;
    }

    private static JobResult Gensig(GlobalIndex index, JobRequest request)
    {
        var result = new JobResult { Total = request.Targets.Count };
        var sigs = new string?[request.Targets.Count];
        Parallel.For(0, request.Targets.Count, i =>
        {
            var (ea, _) = ResolveTarget(index, request.Targets[i]);
            if (ea == BadAddr || index.FuncAt(ea) == null)
            {
                return;
            }

            var sig = SigGen.Make(index, ea, ea, 0);
            sigs[i] = sig.IsEmpty ? null : sig.ToIda();
        });

        for (int i = 0; i < sigs.Length; i++)
        {
            if (sigs[i] == null)
            {
                result.None++;
                result.Lines.Add($"{request.Targets[i]}\t-");
                continue;
            }

            result.Matched++;
            result.Lines.Add($"{request.Targets[i]}\t{sigs[i]}");
        }

        return result;
    }
}
