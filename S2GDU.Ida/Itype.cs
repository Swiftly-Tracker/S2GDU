namespace S2GDU.Ida;

public static class Itype
{
    public const ushort And = 7;
    public const ushort Call = 16;
    public const ushort CallFi = 17;
    public const ushort CallNi = 18;
    public const ushort Div = 35;
    public const ushort Hlt = 40;
    public const ushort Idiv = 41;
    public const ushort Imul = 42;
    public const ushort Int3 = 48;
    public const ushort Ja = 53;
    public const ushort Jcxz = 58;
    public const ushort Jecxz = 59;
    public const ushort Jrcxz = 60;
    public const ushort Jz = 85;
    public const ushort Jmp = 86;
    public const ushort JmpFi = 87;
    public const ushort JmpNi = 88;
    public const ushort JmpShort = 89;
    public const ushort Bt = 12;
    public const ushort Cmp = 27;
    public const ushort Test = 210;
    public const ushort Lea = 92;
    public const ushort Loop = 109;
    public const ushort Loope = 113;
    public const ushort Loopne = 117;
    public const ushort Mov = 122;
    public const ushort Nop = 129;
    public const ushort Push = 143;
    public const ushort Rep = 156;
    public const ushort Repe = 157;
    public const ushort Repne = 158;
    public const ushort Retn = 159;
    public const ushort Retf = 160;
    public const ushort Sub = 209;
    public const ushort Cmova = 229;
    public const ushort Cmovz = 244;
    public const ushort Addss = 425;
    public const ushort Addps = 424;
    public const ushort Comiss = 430;
    public const ushort Divss = 438;
    public const ushort Movaps = 444;
    public const ushort Movss = 450;
    public const ushort Movups = 451;
    public const ushort Mulps = 452;
    public const ushort Mulss = 453;
    public const ushort Subss = 464;
    public const ushort Ucomiss = 465;
    public const ushort Addpd = 519;
    public const ushort Addsd = 520;
    public const ushort Comisd = 526;
    public const ushort Cvtsd2ss = 536;
    public const ushort Cvtss2sd = 538;
    public const ushort Divsd = 544;
    public const ushort Movapd = 552;
    public const ushort Movsd = 563;
    public const ushort Movupd = 564;
    public const ushort Mulpd = 565;
    public const ushort Mulsd = 566;
    public const ushort Subsd = 583;
    public const ushort Ucomisd = 584;
    public const ushort Ud2 = 632;

    public static bool IsCall(ushort itype) => itype is Call or CallFi or CallNi;

    public static bool IsJmp(ushort itype) => itype is Jmp or JmpFi or JmpNi;

    public static bool IsCondJump(ushort itype) => itype is >= Ja and <= Jz or Loop or Loope or Loopne;

    public static bool IsReturn(ushort itype) => itype is Retn or Retf;

    public static bool IsFloat(ushort itype) => itype is Movss or Movsd or Addss or Addsd or Subss or Subsd
        or Mulss or Mulsd or Divss or Divsd or Comiss or Comisd or Ucomiss or Ucomisd or Cvtss2sd or Cvtsd2ss;

    public static bool IsSimd(ushort itype) => itype is Movaps or Movups or Movapd or Movupd or Addps or Addpd or Mulps or Mulpd;
}
