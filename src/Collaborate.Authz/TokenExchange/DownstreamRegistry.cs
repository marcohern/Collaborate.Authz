namespace Collaborate.Authz.TokenExchange;

/// <summary>Stub registry of the resource APIs that accept minted tokens.</summary>
public sealed class DownstreamRegistry : IDownstreamRegistry
{
    private static readonly IReadOnlyDictionary<string, DownstreamService> Services =
        new Dictionary<string, DownstreamService>(StringComparer.Ordinal)
        {
            ["DocumentService"] = new DownstreamService(
                "DocumentService",
                new HashSet<string>(StringComparer.Ordinal) { "doc.read", "doc.write" }),
            ["CommentsService"] = new DownstreamService(
                "CommentsService",
                new HashSet<string>(StringComparer.Ordinal) { "comment.read", "comment.write" }),
        };

    public DownstreamService? Get(string audience) =>
        Services.TryGetValue(audience, out var service) ? service : null;
}
