namespace S2GDU.Ida.Jobs;

public enum JobCommand
{
    Import,
    Track,
    Backtrack,
    Gensig,
}

public sealed class JobRequest
{
    public JobCommand Command { get; set; }
    public string Database { get; set; } = string.Empty;
    public string? Seed { get; set; }
    public string? Clue { get; set; }
    public string? Output { get; set; }
    public List<string> Targets { get; set; } = [];
}

public sealed class JobResult
{
    public int Total { get; set; }
    public int Matched { get; set; }
    public int Ambiguous { get; set; }
    public int None { get; set; }
    public int Rescued { get; set; }
    public int Survived { get; set; }
    public string? Output { get; set; }
    public List<string> Lines { get; set; } = [];
}
