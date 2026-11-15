using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Crawler;

public static class Crawler
{
    public static CrawlResult Crawl(GlobalIndex index, ulong fea)
    {
        var f = index.FuncByStart(fea);
        var identity = f?.Identity ?? new Identity();
        var reinforcement = f?.Reinforcement ?? new Reinforcement();

        var result = new CrawlResult { Identity = identity, Reinforcement = reinforcement };

        result.Anchors.AddRange(SignatureModule.Collect(fea, index));
        result.Anchors.AddRange(StringModule.Collect(fea, index));
        result.Anchors.AddRange(ConvarModule.Collect(fea, index));
        result.Anchors.AddRange(VTableModule.Collect(fea, index));
        result.Anchors.AddRange(LibraryModule.Collect(fea, index));
        result.Anchors.AddRange(RelationalModule.Collect(fea, index));
        result.Anchors.AddRange(DataPtrModule.Collect(fea, index));
        result.Anchors.AddRange(ProximityModule.Collect(fea, index));
        result.Anchors.AddRange(CallChainModule.Collect(fea, index));
        result.Anchors.AddRange(XrefModule.Collect(fea, index));

        return result;
    }
}
