namespace Collaborate.Authz.TokenExchange;

/// <summary>Stub registry of delegation clients. In production this is per-firm client configuration.</summary>
public sealed class ActorTrustPolicy : IActorTrustPolicy
{
    private static readonly IReadOnlyDictionary<string, ActorGrant> Actors =
        new Dictionary<string, ActorGrant>(StringComparer.Ordinal)
        {
            // firm-a's own system may pull document data for its employees, but only doc.* — never comments.
            ["client-sys-a"] = new ActorGrant(
                "client-sys-a",
                "firm-a",
                new HashSet<string>(StringComparer.Ordinal) { "doc.read", "doc.write" }),
        };

    public ActorGrant? Resolve(string actorId) =>
        Actors.TryGetValue(actorId, out var grant) ? grant : null;
}
