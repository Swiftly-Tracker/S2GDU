using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using S2GDU.Ida.Generated;
using S2GDU.Ida.Model;
using S2GDU.Ida.Rtti;

namespace S2GDU.Ida.Index;

public static unsafe class IndexBuilder
{
    private const ulong BadAddr = ulong.MaxValue;

    private const int InfLflags = 3;
    private const int InfImageBase = 93;
    private const ulong Lflg64Bit = 0x4;

    private const int SegPermOffset = 42;
    private const int SegTypeOffset = 184;

    private const int InsnSizeOffset = 26;
    private const int OpsOffset = 40;
    private const int OpSize = 40;
    private const int OpOffbOffset = 2;
    private const int MaxOps = 8;

    private const ulong MsCls = 0x600;
    private const ulong FfData = 0x400;
    private const ulong DtType = 0xF0000000;
    private const ulong FfStrlit = 0x50000000;

    private const int GtaFuncNargs = 23;
    private const int GtaFuncArg = 25;

    private const ushort RegRsp = 4;
    private const ushort RegRbp = 5;
    private const ushort RegRbx = 3;
    private const ushort RegRcx = 1;
    private const ushort RegRdi = 7;
    private const ushort GprCount = 16;
    private const uint VolatileWin64 = 0xF07;
    private const uint VolatileSysV = 0xFC7;
    private const ulong MaxFieldOffset = 1 << 20;

    private static readonly string[] DataSegmentMarkers = [".data", ".rodata", ".rdata", "__const", "__data"];
    private static readonly string[] DummyPrefixes = ["off_", "qword_", "unk_", "byte_", "word_", "dword_"];

    [ThreadStatic]
    private static List<(ulong Ea, string Name)>? _imports;

    public static GlobalIndex Build(Action<string>? stage = null)
    {
        IdaKernel.AssertOwner();

        bool is64 = (IdaNative.getinf(InfLflags) & (nuint)Lflg64Bit) != 0;
        ulong imageBase = IdaNative.getinf(InfImageBase);
        string binaryName = RootFileName();
        bool linux = binaryName.Contains(".so", StringComparison.Ordinal) || binaryName.Contains(".dylib", StringComparison.Ordinal);

        stage?.Invoke("segments");
        var segments = ReadSegments();

        stage?.Invoke("names");
        var names = ReadNames();

        stage?.Invoke("functions");
        var (functions, instructions, callees, jumpless) = DecodeFunctions(is64, linux);
        _ = jumpless;

        stage?.Invoke("strings");
        var (stringToFuncs, funcToStrings) = ReadStrings();

        stage?.Invoke("imports");
        var imports = ReadImports();

        var byStart = new Dictionary<ulong, FunctionInfo>(functions.Length);
        foreach (var f in functions)
        {
            byStart.TryAdd(f.Start, f);
        }

        var index = new GlobalIndex
        {
            BinaryName = binaryName,
            Is64Bit = is64,
            IsLinux = linux,
            ImageBase = imageBase,
            Functions = functions,
            Instructions = instructions,
            Segments = segments,
            CodeSections = [.. segments.Where(s => s.IsCode && s.Bytes != null)],
            ByStart = byStart,
            StringToFuncs = stringToFuncs,
            FuncToStrings = funcToStrings,
        };
        index.Seal();

        stage?.Invoke("vtables");
        BuildVTables(index, names);

        stage?.Invoke("callgraph");
        BuildCallGraph(index, callees);

        stage?.Invoke("data pointers");
        BuildDataPointers(index);

        stage?.Invoke("library");
        BuildLibrary(index, imports);

        stage?.Invoke("convars");
        BuildDataRefs(index);
        BuildConvars(index);

        stage?.Invoke("metadata");
        FinishMetadata(index);

        return index;
    }

    private static string RootFileName()
    {
        byte* buf = stackalloc byte[1024];
        nint n = IdaNative.get_root_filename(buf, 1024);
        return n <= 0 ? string.Empty : Marshal.PtrToStringUTF8((nint)buf) ?? string.Empty;
    }

    private static string ReadQString(QString* q)
    {
        string s = q->Read();
        int nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }

    private static SegmentInfo[] ReadSegments()
    {
        int count = IdaNative.get_segm_qty();
        var list = new List<SegmentInfo>(count);
        for (int i = 0; i < count; i++)
        {
            byte* seg = (byte*)IdaNative.getnseg(i);
            if (seg == null)
            {
                continue;
            }

            ulong start = *(ulong*)seg;
            ulong end = *(ulong*)(seg + 8);
            byte perm = seg[SegPermOffset];
            byte type = seg[SegTypeOffset];

            QString q = default;
            IdaNative.get_segm_name(&q, seg, 0);
            string name = ReadQString(&q);
            q.Dispose();

            byte[]? bytes = null;
            ulong size = end > start ? end - start : 0;
            if (type != SegmentInfo.TypeBss && size > 0 && size < int.MaxValue)
            {
                bytes = new byte[size];
                fixed (byte* p = bytes)
                {
                    if (IdaNative.get_bytes(p, (nint)size, start, 0, null) <= 0)
                    {
                        bytes = null;
                    }
                }
            }

            list.Add(new SegmentInfo { Start = start, End = end, Name = name, Type = type, Perm = perm, Bytes = bytes });
        }

        list.Sort((a, b) => a.Start.CompareTo(b.Start));
        return [.. list];
    }

    private static SortedList<ulong, string> ReadNames()
    {
        nuint count = IdaNative.get_nlist_size();
        var names = new SortedList<ulong, string>((int)count);
        for (nuint i = 0; i < count; i++)
        {
            ulong ea = IdaNative.get_nlist_ea(i);
            byte* name = IdaNative.get_nlist_name(i);
            if (name == null || name[0] == 0)
            {
                continue;
            }

            names[ea] = Marshal.PtrToStringUTF8((nint)name) ?? string.Empty;
        }

        return names;
    }

    private static ulong FuncStartOf(ulong ea)
    {
        byte* f = (byte*)IdaNative.get_func(ea);
        return f == null ? BadAddr : *(ulong*)f;
    }

    private static (FunctionInfo[] Functions, InsnRecord[] Instructions, List<ulong>[] Callees, int Unused) DecodeFunctions(bool is64, bool linux)
    {
        uint thisBit = 1u << (linux ? RegRdi : RegRcx);
        uint clobber = linux ? VolatileSysV : VolatileWin64;
        var fields = new List<FieldAccess>();
        var thisCalls = new HashSet<ulong>();
        var others = new List<FieldAccess>();
        var otherSeen = new HashSet<int>();
        int count = (int)IdaNative.get_func_qty();
        var functions = new List<FunctionInfo>(count);
        var callees = new List<List<ulong>>(count);
        var insns = new List<InsnRecord>(count * 32);

        byte* buf = stackalloc byte[Insn.BufferSize];
        var heads = new List<ulong>(1024);
        var itypes = new List<ushort>(1024);
        var targets = new List<List<ulong>?>(1024);
        var dataRefs = new HashSet<ulong>();
        var dataOrder = new List<ulong>();
        var constants = new SortedSet<ulong>();
        var calleeSet = new List<ulong>();

        for (int i = 0; i < count; i++)
        {
            byte* fp = (byte*)IdaNative.getn_func((nuint)i);
            if (fp == null)
            {
                continue;
            }

            ulong start = *(ulong*)fp;
            ulong end = *(ulong*)(fp + 8);

            QString qn = default;
            IdaNative.get_func_name(&qn, start);
            string name = ReadQString(&qn);
            qn.Dispose();

            var identity = ReadIdentity(start);

            heads.Clear();
            itypes.Clear();
            targets.Clear();
            dataRefs.Clear();
            dataOrder.Clear();
            constants.Clear();
            calleeSet.Clear();
            fields.Clear();
            thisCalls.Clear();
            others.Clear();
            otherSeen.Clear();
            uint alias = thisBit;

            int insnStart = insns.Count;
            byte prologue = 0;
            bool inPrologue = true;
            ulong prologueLimit = Math.Min(start + 32, end);
            ulong thunkTarget = BadAddr;
            ulong firstJump = BadAddr;
            uint flags = 0;
            uint size = (uint)(end - start);

            ulong ea = start;
            while (ea < end && ea != BadAddr)
            {
                if (Insn.TryDecode(ea, buf))
                {
                    ushort itype = Insn.Itype(buf);
                    byte len = (byte)*(ushort*)(buf + InsnSizeOffset);
                    byte op0 = Insn.OpType(buf, 0);

                    insns.Add(new InsnRecord((uint)(ea - start), itype, len, ImmOffset(buf)));
                    bool passesThis = (alias & thisBit) != 0 && (Itype.IsCall(itype) || Itype.IsJmp(itype)) && op0 is Insn.OpNear or Insn.OpFar;
                    RecordOther(buf, (uint)(ea - start), alias, others, otherSeen);
                    if (alias != 0)
                    {
                        alias = TrackThis(buf, itype, (uint)(ea - start), alias, clobber, fields);
                    }

                    heads.Add(ea);
                    itypes.Add(itype);

                    if (Itype.IsCall(itype) && op0 is Insn.OpReg or Insn.OpPhrase or Insn.OpDispl)
                    {
                        identity.HasIndirectCall = true;
                    }

                    if (Itype.IsJmp(itype))
                    {
                        if (op0 is Insn.OpReg or Insn.OpPhrase)
                        {
                            identity.HasSwitch = true;
                        }

                        if (op0 is Insn.OpNear or Insn.OpFar)
                        {
                            ulong jt = Insn.OpAddr(buf, 0);
                            if (ea == start)
                            {
                                firstJump = jt;
                            }

                            if (size < 64 && thunkTarget == BadAddr && FuncStartOf(jt) == jt)
                            {
                                thunkTarget = jt;
                            }
                        }
                    }

                    if (itype is >= Itype.Ja and <= Itype.Jz && op0 == Insn.OpNear && Insn.OpAddr(buf, 0) < ea)
                    {
                        flags |= IdentityFlags.HasLoop;
                    }

                    if (itype is Itype.Loop or Itype.Loope or Itype.Loopne)
                    {
                        flags |= IdentityFlags.HasLoop;
                    }

                    if (Itype.IsFloat(itype))
                    {
                        flags |= IdentityFlags.HasFloatOps;
                    }

                    if (Itype.IsSimd(itype))
                    {
                        flags |= IdentityFlags.HasSimd;
                    }

                    if (itype is Itype.Div or Itype.Idiv)
                    {
                        flags |= IdentityFlags.HasDiv;
                    }

                    if (itype == Itype.Imul)
                    {
                        flags |= IdentityFlags.HasMul;
                    }

                    if (itype == Itype.Sub && op0 == Insn.OpReg && Insn.OpRegister(buf, 0) == RegRsp
                        && Insn.OpType(buf, 1) == Insn.OpImm && Insn.OpValue(buf, 1) > 256)
                    {
                        flags |= IdentityFlags.HasLargeStack;
                    }

                    if (itype is Itype.Rep or Itype.Repe or Itype.Repne)
                    {
                        flags |= IdentityFlags.HasRepOps;
                    }

                    if (itype is >= Itype.Cmova and <= Itype.Cmovz)
                    {
                        flags |= IdentityFlags.HasCmov;
                    }

                    CollectConstants(buf, itype, constants);

                    if (inPrologue)
                    {
                        if (ea < prologueLimit && IsPrologue(buf, itype))
                        {
                            prologue += len;
                            if (prologue >= Config.MaxPrologueSkip)
                            {
                                inPrologue = false;
                            }
                        }
                        else
                        {
                            inPrologue = false;
                        }
                    }

                    List<ulong>? local = null;
                    for (ulong to = IdaNative.get_first_fcref_from(ea); to != BadAddr; to = IdaNative.get_next_fcref_from(ea, to))
                    {
                        ulong target = FuncStartOf(to);
                        if (target != BadAddr && target != start)
                        {
                            calleeSet.Add(target);
                            if (passesThis && target == to)
                            {
                                thisCalls.Add(target);
                            }
                        }

                        if (!Itype.IsCall(itype) && to >= start && to < end)
                        {
                            (local ??= []).Add(to);
                        }
                    }

                    targets.Add(local);

                    for (ulong to = IdaNative.get_first_dref_from(ea); to != BadAddr; to = IdaNative.get_next_dref_from(ea, to))
                    {
                        if (dataRefs.Contains(to) || !IsPointerData(to, is64))
                        {
                            continue;
                        }

                        dataRefs.Add(to);
                        dataOrder.Add(to);
                    }
                }
                else
                {
                    inPrologue = false;
                }

                ea = IdaNative.next_head(ea, end);
            }

            identity.StructFlags = flags;

            var (bb, cyclomatic) = FlowStats(heads, itypes, targets, start, end);
            var rf = new Reinforcement { Size = size, BbCount = bb, Cyclomatic = cyclomatic };
            rf.Constants.AddRange(constants);

            functions.Add(new FunctionInfo
            {
                Start = start,
                End = end,
                Name = name,
                InsnStart = insnStart,
                InsnCount = insns.Count - insnStart,
                PrologueLength = prologue,
                ThunkTarget = thunkTarget,
                FirstJumpTarget = firstJump,
                DataRefs = [.. dataOrder],
                ThisFields = fields.Count == 0 ? [] : [.. fields],
                ThisCalls = thisCalls.Count == 0 ? [] : [.. thisCalls],
                OtherFields = others.Count == 0 ? [] : [.. others],
                Identity = identity,
                Reinforcement = rf,
            });
            callees.Add([.. calleeSet]);
        }

        var order = Enumerable.Range(0, functions.Count).OrderBy(i => functions[i].Start).ToArray();
        return ([.. order.Select(i => functions[i])], [.. insns], [.. order.Select(i => callees[i])], 0);
    }

    private static void RecordOther(byte* buf, uint delta, uint alias, List<FieldAccess> others, HashSet<int> seen)
    {
        for (int i = 0; i < 2; i++)
        {
            if (Insn.OpType(buf, i) != Insn.OpDispl || Insn.OpHasSib(buf, i))
            {
                continue;
            }

            ushort r = Insn.OpRegister(buf, i);
            ulong disp = Insn.OpAddr(buf, i);
            if (r < GprCount && r is not (RegRsp or RegRbp) && (alias & (1u << r)) == 0
                && disp >= MinOtherFieldOffset && disp < MaxFieldOffset && others.Count < MaxOtherFields && seen.Add((int)disp))
            {
                others.Add(new FieldAccess(delta, (int)disp));
            }
        }
    }

    private const int MinOtherFieldOffset = 128;
    private const int MaxOtherFields = 64;

    private static uint TrackThis(byte* buf, ushort itype, uint delta, uint alias, uint clobber, List<FieldAccess> fields)
    {
        for (int i = 0; i < 2; i++)
        {
            byte t = Insn.OpType(buf, i);
            if (t is not (Insn.OpPhrase or Insn.OpDispl) || Insn.OpHasSib(buf, i))
            {
                continue;
            }

            ushort r = Insn.OpRegister(buf, i);
            ulong disp = t == Insn.OpDispl ? Insn.OpAddr(buf, i) : 0;
            if (r < GprCount && (alias & (1u << r)) != 0 && disp < MaxFieldOffset)
            {
                fields.Add(new FieldAccess(delta, (int)disp));
            }
        }

        if (Itype.IsCall(itype))
        {
            return alias & ~clobber;
        }

        if (Insn.OpType(buf, 0) != Insn.OpReg || itype is Itype.Cmp or Itype.Test or Itype.Bt or Itype.Push)
        {
            return alias;
        }

        ushort dst = Insn.OpRegister(buf, 0);
        if (dst >= GprCount)
        {
            return alias;
        }

        ushort src = Insn.OpRegister(buf, 1);
        bool copy = itype == Itype.Mov && Insn.OpType(buf, 1) == Insn.OpReg && src < GprCount && (alias & (1u << src)) != 0;
        return copy ? alias | (1u << dst) : alias & ~(1u << dst);
    }

    private static byte ImmOffset(byte* buf)
    {
        for (int i = 0; i < MaxOps; i++)
        {
            byte* op = buf + OpsOffset + i * OpSize;
            if (op[1] == Insn.OpVoid)
            {
                return 0;
            }

            if (op[OpOffbOffset] > 0)
            {
                return op[OpOffbOffset];
            }
        }

        return 0;
    }

    private static bool IsPrologue(byte* buf, ushort itype)
    {
        byte t0 = Insn.OpType(buf, 0);
        ushort r0 = Insn.OpRegister(buf, 0);
        return itype switch
        {
            Itype.Push => t0 == Insn.OpReg && (r0 == RegRbp || r0 == RegRbx || r0 is >= 12 and <= 15),
            Itype.Mov => t0 == Insn.OpReg && Insn.OpType(buf, 1) == Insn.OpReg && r0 == RegRbp && Insn.OpRegister(buf, 1) == RegRsp,
            Itype.Sub => t0 == Insn.OpReg && r0 == RegRsp,
            Itype.Lea => t0 == Insn.OpReg && r0 == RegRbp,
            Itype.And => t0 == Insn.OpReg && r0 == RegRsp,
            _ => false,
        };
    }

    private static void CollectConstants(byte* buf, ushort itype, SortedSet<ulong> constants)
    {
        bool floatLoad = itype is Itype.Movss or Itype.Movsd;
        for (int i = 0; i < MaxOps; i++)
        {
            byte type = Insn.OpType(buf, i);
            if (type == Insn.OpVoid)
            {
                break;
            }

            if (type == Insn.OpImm)
            {
                ulong v = Insn.OpValue(buf, i);
                if (v > 0xFF && v != 0xFFFFFFFF && v != ulong.MaxValue && v != 0x100 && v != 0x200 && v != 0x400 && v != 0x800)
                {
                    constants.Add(v);
                }
            }

            if (floatLoad && type == Insn.OpMem)
            {
                ulong addr = Insn.OpAddr(buf, i);
                if (addr != BadAddr)
                {
                    uint raw = IdaNative.get_dword(addr);
                    if (raw != 0 && raw != 0x3F800000)
                    {
                        constants.Add(raw);
                    }
                }
            }
        }
    }

    private static bool IsPointerData(ulong ea, bool is64)
    {
        byte* seg = (byte*)IdaNative.getseg(ea);
        if (seg == null)
        {
            return false;
        }

        byte type = seg[SegTypeOffset];
        byte perm = seg[SegPermOffset];
        if (type != SegmentInfo.TypeData && perm != (SegmentInfo.PermRead | SegmentInfo.PermWrite) && perm != SegmentInfo.PermRead)
        {
            return false;
        }

        ulong flags = IdaNative.get_flags_ex(ea, 0);
        bool isData = (flags & MsCls) == FfData;
        if (!isData || (flags & DtType) == FfStrlit)
        {
            return false;
        }

        ulong itemEnd = IdaNative.get_item_end(ea);
        return itemEnd > ea && itemEnd - ea >= (ulong)(is64 ? 8 : 4);
    }

    private static (ushort Bb, ushort Cyclomatic) FlowStats(List<ulong> heads, List<ushort> itypes, List<List<ulong>?> targets, ulong start, ulong end)
    {
        if (heads.Count == 0)
        {
            return (0, 2);
        }

        var headSet = new HashSet<ulong>(heads);
        var leaders = new HashSet<ulong> { heads[0] };
        for (int i = 0; i < heads.Count; i++)
        {
            ushort it = itypes[i];
            bool terminator = IsTerminator(it);
            if (targets[i] is { } t)
            {
                foreach (ulong to in t)
                {
                    if (headSet.Contains(to))
                    {
                        leaders.Add(to);
                    }
                }
            }

            if (terminator && i + 1 < heads.Count)
            {
                leaders.Add(heads[i + 1]);
            }
        }

        int edges = 0;
        for (int i = 0; i < heads.Count; i++)
        {
            bool last = i + 1 == heads.Count || leaders.Contains(heads[i + 1]);
            if (!last)
            {
                continue;
            }

            ushort it = itypes[i];
            bool hasNext = i + 1 < heads.Count;
            if (IsTerminator(it))
            {
                int succ = 0;
                if (targets[i] is { } t)
                {
                    succ = t.Where(headSet.Contains).Distinct().Count();
                }

                if (Itype.IsCondJump(it) && hasNext && !(targets[i]?.Contains(heads[i + 1]) ?? false))
                {
                    succ++;
                }

                edges += succ;
            }
            else if (hasNext)
            {
                edges++;
            }
        }

        int blocks = leaders.Count;
        return ((ushort)blocks, (ushort)(edges - blocks + 2));
    }

    private static bool IsTerminator(ushort itype) =>
        Itype.IsJmp(itype) || itype == Itype.JmpShort || Itype.IsCondJump(itype) || Itype.IsReturn(itype) || itype is Itype.Hlt or Itype.Ud2;

    private static Identity ReadIdentity(ulong fea)
    {
        var id = new Identity();
        TypeInfo ti = default;
        try
        {
            if (IdaNative.get_tinfo(&ti, fea) == 0)
            {
                return id;
            }

            long nargs = (long)(nint)IdaNative.get_tinfo_property(ti.Typid, GtaFuncNargs);
            if (nargs < 0 || nargs > 255)
            {
                return id;
            }

            id.ParamCount = (byte)nargs;
            id.ReturnType = PrintArg(ti.Typid, -1);
            id.HasReturn = id.ReturnType != "void";
            for (int i = 0; i < nargs; i++)
            {
                id.ParamTypes.Add(PrintArg(ti.Typid, i));
            }
        }
        finally
        {
            ti.Dispose();
        }

        return id;
    }

    private static string PrintArg(ulong typid, int n)
    {
        TypeInfo arg = default;
        arg.Typid = IdaNative.get_tinfo_property(typid, GtaFuncArg + n);
        try
        {
            QString q = default;
            string text = IdaNative.print_tinfo(&q, null, 0, 0, 0, &arg, null, null) != 0 ? ReadQString(&q) : string.Empty;
            q.Dispose();
            return text;
        }
        finally
        {
            arg.Dispose();
        }
    }

    private static (Dictionary<string, List<ulong>>, Dictionary<ulong, List<string>>) ReadStrings()
    {
        var s2f = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
        var f2s = new Dictionary<ulong, List<string>>();
        nuint count = IdaNative.get_strlist_qty();
        var info = stackalloc ulong[2];

        for (nuint i = 0; i < count; i++)
        {
            if (IdaNative.get_strlist_item(info, i) == 0)
            {
                continue;
            }

            ulong ea = info[0];
            int length = *(int*)((byte*)info + 8);
            int type = *(int*)((byte*)info + 12);
            if (length < 6)
            {
                continue;
            }

            QString q = default;
            nint got = IdaNative.get_strlit_contents(&q, ea, (nuint)length, type, null, 0);
            string s = got > 0 ? ReadQString(&q) : string.Empty;
            q.Dispose();
            if (got <= 0 || s is "true" or "false" or "null")
            {
                continue;
            }

            for (ulong from = IdaNative.get_first_dref_to(ea); from != BadAddr; from = IdaNative.get_next_dref_to(ea, from))
            {
                ulong fea = FuncStartOf(from);
                if (fea == BadAddr)
                {
                    continue;
                }

                if (!s2f.TryGetValue(s, out var funcs))
                {
                    s2f[s] = funcs = [];
                }

                funcs.Add(fea);

                if (!f2s.TryGetValue(fea, out var strs))
                {
                    f2s[fea] = strs = [];
                }

                strs.Add(s);
            }
        }

        Parallel.ForEach(s2f.Values, l => SortUnique(l));
        Parallel.ForEach(f2s.Values, l =>
        {
            l.Sort(StringComparer.Ordinal);
            int w = 0;
            for (int r = 0; r < l.Count; r++)
            {
                if (w == 0 || !string.Equals(l[w - 1], l[r], StringComparison.Ordinal))
                {
                    l[w++] = l[r];
                }
            }

            l.RemoveRange(w, l.Count - w);
        });

        return (s2f, f2s);
    }

    private static void SortUnique(List<ulong> l)
    {
        l.Sort();
        int w = 0;
        for (int r = 0; r < l.Count; r++)
        {
            if (w == 0 || l[w - 1] != l[r])
            {
                l[w++] = l[r];
            }
        }

        l.RemoveRange(w, l.Count - w);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnImport(ulong ea, byte* name, ulong ordinal, void* param)
    {
        if (ea != BadAddr && name != null && name[0] != 0)
        {
            _imports!.Add((ea, Marshal.PtrToStringUTF8((nint)name) ?? string.Empty));
        }

        return 1;
    }

    private static List<(ulong Ea, string Name)> ReadImports()
    {
        _imports = [];
        uint count = IdaNative.get_import_module_qty();
        delegate* unmanaged[Cdecl]<ulong, byte*, ulong, void*, int> callback = &OnImport;
        for (int i = 0; i < count; i++)
        {
            QString q = default;
            byte ok = IdaNative.get_import_module_name(&q, i);
            q.Dispose();
            if (ok == 0)
            {
                continue;
            }

            IdaNative.enum_import_names(i, callback, null);
        }

        var result = _imports;
        _imports = null;
        return result;
    }

    private static bool IsDataSegment(SegmentInfo seg, bool includeVTableMarkers)
    {
        if (seg.Type == SegmentInfo.TypeData)
        {
            return true;
        }

        int markers = includeVTableMarkers ? DataSegmentMarkers.Length : 3;
        for (int i = 0; i < markers; i++)
        {
            if (seg.Name.Contains(DataSegmentMarkers[i], StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsVTableName(string name) =>
        name.StartsWith("_ZTV", StringComparison.Ordinal)
        || name.StartsWith("??_7", StringComparison.Ordinal)
        || name.Contains("vtable for", StringComparison.Ordinal)
        || name.Contains("`vftable'", StringComparison.Ordinal)
        || name.Contains("_vftable", StringComparison.Ordinal);

    private static void BuildVTables(GlobalIndex index, SortedList<ulong, string> names)
    {
        int ptr = index.PointerSize;
        var eas = names.Keys;
        var values = names.Values;

        foreach (var seg in index.Segments)
        {
            if (!IsDataSegment(seg, includeVTableMarkers: true))
            {
                continue;
            }

            int first = LowerBound(eas, seg.Start);
            for (int n = first; n < eas.Count && eas[n] < seg.End; n++)
            {
                ulong ea = eas[n];
                string vtName = values[n];
                if (!IsVTableName(vtName))
                {
                    continue;
                }

                var vt = new VTableEntry { Name = vtName, StartEa = ea, Demangled = RttiNames.ExtractClassFromMangled(vtName) };
                ulong p = ea;
                bool itanium = vtName.StartsWith("_ZTV", StringComparison.Ordinal);
                if (itanium)
                {
                    p += (ulong)(ptr * 2);
                }

                while (p < seg.End)
                {
                    if (p != ea && names.TryGetValue(p, out string? next) && !IsDummyName(next))
                    {
                        break;
                    }

                    ulong target = index.ReadPointer(p);
                    if (target == 0 && itanium)
                    {
                        vt.Slots.Add(0);
                        p += (ulong)ptr;
                        continue;
                    }

                    if (target == 0 || target == BadAddr || (!index.Is64Bit && target == uint.MaxValue))
                    {
                        break;
                    }

                    if (!index.ByStart.TryGetValue(target, out var f))
                    {
                        if (itanium)
                        {
                            break;
                        }

                        vt.Slots.Add(0);
                        p += (ulong)ptr;
                        continue;
                    }

                    if (f.Size < 64 && f.ThunkTarget != BadAddr)
                    {
                        target = f.ThunkTarget;
                    }

                    uint slot = (uint)vt.Slots.Count;
                    vt.Slots.Add(target);
                    if (!index.FuncToVTables.TryGetValue(target, out var refs))
                    {
                        index.FuncToVTables[target] = refs = [];
                    }

                    refs.Add(new VTableRef(vtName, slot));

                    p += (ulong)ptr;
                    if (vt.Slots.Count > 500)
                    {
                        break;
                    }
                }

                while (vt.Slots.Count > 0 && vt.Slots[^1] == 0)
                {
                    vt.Slots.RemoveAt(vt.Slots.Count - 1);
                }

                if (vt.Slots.Count > 0)
                {
                    index.VTables[vtName] = vt;
                }
            }
        }

        foreach (var vt in index.VTables.Values.OrderBy(v => v.StartEa))
        {
            if (vt.Demangled.Length > 0
                && (!index.ClassToVtName.TryGetValue(vt.Demangled, out string? prev) || index.VTables[prev].Slots.Count < vt.Slots.Count))
            {
                index.ClassToVtName[vt.Demangled] = vt.Name;
            }
        }
    }

    private static bool IsDummyName(string name)
    {
        foreach (string prefix in DummyPrefixes)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static int LowerBound(IList<ulong> keys, ulong value)
    {
        int lo = 0;
        int hi = keys.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (keys[mid] < value)
            {
                lo = mid + 1;
            }
            else
            {
                hi = mid;
            }
        }

        return lo;
    }

    private static void BuildCallGraph(GlobalIndex index, List<ulong>[] callees)
    {
        for (int i = 0; i < index.Functions.Length; i++)
        {
            ulong fea = index.Functions[i].Start;
            foreach (ulong target in callees[i])
            {
                if (!index.Callees.TryGetValue(fea, out var cl))
                {
                    index.Callees[fea] = cl = [];
                }

                cl.Add(target);

                if (!index.Callers.TryGetValue(target, out var cr))
                {
                    index.Callers[target] = cr = [];
                }

                cr.Add(fea);
            }
        }

        Parallel.ForEach(index.Callees.Values, SortUnique);
        Parallel.ForEach(index.Callers.Values, SortUnique);
    }

    private static void BuildDataPointers(GlobalIndex index)
    {
        int ptr = index.PointerSize;
        var ranges = index.VTables.Values
            .Select(v => (Start: v.StartEa + (ulong)(2 * ptr), End: v.StartEa + (ulong)(2 * ptr) + (ulong)(v.Slots.Count * ptr)))
            .OrderBy(r => r.Start)
            .ThenBy(r => r.End)
            .ToArray();
        var starts = ranges.Select(r => r.Start).ToArray();

        foreach (var seg in index.Segments)
        {
            if (!IsDataSegment(seg, includeVTableMarkers: false) || seg.Bytes == null)
            {
                continue;
            }

            bool isDotData = seg.Name.Contains(".data", StringComparison.Ordinal);
            for (ulong ea = seg.Start; ea + (ulong)ptr <= seg.End; ea += (ulong)ptr)
            {
                ulong value = index.ReadPointer(ea);
                if (value == 0 || value == BadAddr || !index.ByStart.TryGetValue(value, out var f))
                {
                    continue;
                }

                int r = Array.BinarySearch(starts, ea);
                if (r < 0)
                {
                    r = ~r - 1;
                }
                else
                {
                    while (r + 1 < starts.Length && starts[r + 1] == ea)
                    {
                        r++;
                    }
                }

                if (r >= 0 && ea >= ranges[r].Start && ea < ranges[r].End)
                {
                    continue;
                }

                ulong final = f.Size < 64 && f.ThunkTarget != BadAddr ? f.ThunkTarget : value;
                index.DataFuncPtrs.Add(new DataFuncPtr(ea, final));

                if (isDotData)
                {
                    if (!index.FuncToDataSegPtrs.TryGetValue(final, out var l))
                    {
                        index.FuncToDataSegPtrs[final] = l = [];
                    }

                    l.Add(ea);
                }
            }
        }
    }

    private static void BuildLibrary(GlobalIndex index, List<(ulong Ea, string Name)> imports)
    {
        foreach (var (ea, name) in imports)
        {
            index.LibraryFuncs.Add(ea);
            index.LibraryNames[ea] = name;
        }

        foreach (var f in index.Functions)
        {
            string n = f.Name;
            if (n.Length == 0)
            {
                continue;
            }

            bool lib = n.Contains("@plt", StringComparison.Ordinal)
                || n.Contains(".plt", StringComparison.Ordinal)
                || n.StartsWith("j_", StringComparison.Ordinal)
                || n.StartsWith("_imp_", StringComparison.Ordinal)
                || n.StartsWith("std::", StringComparison.Ordinal)
                || n.StartsWith("__cxa_", StringComparison.Ordinal)
                || n.StartsWith("__gxx_", StringComparison.Ordinal);

            if (lib)
            {
                index.LibraryFuncs.Add(f.Start);
                index.LibraryNames.TryAdd(f.Start, n);
            }
        }
    }

    private static void BuildDataRefs(GlobalIndex index)
    {
        foreach (var f in index.Functions)
        {
            foreach (ulong d in f.DataRefs)
            {
                if (!index.DataRefToFuncs.TryGetValue(d, out var l))
                {
                    index.DataRefToFuncs[d] = l = [];
                }

                l.Add(f.Start);
            }
        }
    }

    public static bool IsConvarString(string s)
    {
        if (s.Length < 4 || s.Length > 64)
        {
            return false;
        }

        if (!(s.StartsWith("sv_", StringComparison.Ordinal) || s.StartsWith("mp_", StringComparison.Ordinal)
            || s.StartsWith("cl_", StringComparison.Ordinal) || s.StartsWith("tv_", StringComparison.Ordinal)
            || s.StartsWith("net_", StringComparison.Ordinal) || s.StartsWith("r_", StringComparison.Ordinal)
            || s.StartsWith("mat_", StringComparison.Ordinal) || s.StartsWith("snd_", StringComparison.Ordinal)
            || s.StartsWith("demo_", StringComparison.Ordinal) || s.StartsWith("con_", StringComparison.Ordinal)))
        {
            return false;
        }

        foreach (char c in s)
        {
            if (c != '_' && !char.IsAsciiLetterOrDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    public static string PickBestConvarString(IEnumerable<string> strings)
    {
        string best = string.Empty;
        foreach (string s in strings)
        {
            if (IsConvarString(s) && s.Length > best.Length)
            {
                best = s;
            }
        }

        return best;
    }

    private static void BuildConvars(GlobalIndex index)
    {
        var scanned = new HashSet<ulong>();
        foreach (var (name, funcs) in index.StringToFuncs.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            if (!IsConvarString(name))
            {
                continue;
            }

            foreach (ulong fea in funcs)
            {
                foreach (ulong qword in index.CollectDataXrefs(fea))
                {
                    if (scanned.Add(qword))
                    {
                        IndexQword(index, qword);
                    }
                }
            }
        }
    }

    private static void IndexQword(GlobalIndex index, ulong qword)
    {
        var funcs = index.FunctionsReferencingData(qword);
        if (funcs.Count == 0)
        {
            return;
        }

        string convar = string.Empty;
        var regFuncs = new HashSet<ulong>();
        foreach (ulong fea in funcs)
        {
            if (!index.FuncToStrings.TryGetValue(fea, out var strs))
            {
                continue;
            }

            string candidate = PickBestConvarString(strs);
            if (candidate.Length == 0)
            {
                continue;
            }

            if (convar.Length == 0)
            {
                convar = candidate;
            }
            else if (candidate != convar)
            {
                return;
            }

            regFuncs.Add(fea);
        }

        if (convar.Length == 0)
        {
            return;
        }

        index.ConvarQwordToName[qword] = convar;

        bool hasNonReg = funcs.Count > regFuncs.Count;
        if (!index.ConvarNameToFuncs.TryGetValue(convar, out var existing))
        {
            index.ConvarNameToFuncs[convar] = existing = [];
        }

        foreach (ulong fea in funcs)
        {
            if (hasNonReg && regFuncs.Contains(fea))
            {
                continue;
            }

            if (!existing.Contains(fea))
            {
                existing.Add(fea);
            }
        }
    }

    private static void FinishMetadata(GlobalIndex index)
    {
        Parallel.ForEach(index.Functions, f =>
        {
            var rf = f.Reinforcement;
            rf.CallerCount = index.CallerCount(f.Start);
            rf.CalleeCount = index.CalleeCount(f.Start);
            if (index.FuncToStrings.TryGetValue(f.Start, out var strs))
            {
                foreach (string s in strs)
                {
                    if (System.Text.Encoding.UTF8.GetByteCount(s) >= Config.MinStringLength)
                    {
                        rf.Strings.Add(s);
                    }
                }
            }
        });
    }
}
