namespace S2GDU.Ida;

public static class Config
{
    public const uint MaxItemsPerModule = 5;

    public const uint MinSignatureLength = 8;
    public const uint MaxPrologueSkip = 24;
    public const uint MinFuncSizeForSkip = 40;

    public const uint MinStringLength = 8;
    public const uint MinProximityStringLength = 10;
    public const uint MaxRareStringRefs = 5;

    public const uint MaxRelationalFanout = 10;

    public const uint MaxNeighborDistance = 0x40000;

    public const int IdentityParamTolerance = 2;

    public const uint SizeTolerancePct = 30;
    public const uint MinSizeToleranceAbs = 4;
    public const int BbCountTolerance = 3;
    public const int CyclomaticTolerance = 4;
    public const uint CallerTolerancePct = 50;
    public const uint CalleeTolerancePct = 50;

    public const uint MinConsensusVotes = 2;
    public const uint MinAnyVotes = 3;

    public const uint ProximityDeltaTolerance = 0x2000;

    public const uint VTableSlotBaseTolerance = 10;
    public const uint MaxCandidateTries = 5;

    public const uint DataPtrSectionTolerance = 0x80000;
    public const uint DataPtrCalTolerance = 0x40000;
    public const float DataPtrCalMinRf = 0.55f;
    public const uint DataPtrCalMaxCandidates = 30;

    public const float RfTiebreakerMinDiff = 0.3f;

    public const ushort MidContextNone = 0xFFFF;
    public const uint MidContextRadius = 5;
    public const uint MidContextMinScore = 6;

    public const uint CallChainMaxDepth = 6;
    public const uint CallChainMaxAnchors = 5;
    public const uint CallChainMaxVisit = 500;

    public const uint XrefMaxDepth = 4;
    public const uint XrefMaxAnchors = 3;
    public const uint XrefMaxDataRefs = 20;

    private static readonly string[] AntiAnchorPatterns =
    [
        "memcpy", "memset", "memmove", "memcmp",
        "malloc", "calloc", "realloc", "free",
        "printf", "sprintf", "snprintf", "fprintf",
        "strlen", "strcpy", "strncpy", "strcmp", "strcat",
        "operator new", "operator delete",
        "__cxa_", "__gxx_",
        "_Znw", "_Zdl", "_Zna", "_Zda",
    ];

    public static bool IsAntiAnchorName(string? name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return false;
        }

        foreach (string pattern in AntiAnchorPatterns)
        {
            if (name.Contains(pattern, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
