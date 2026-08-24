namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// A downstream resource service that will accept the minted token. <see cref="AllowedScopes"/> bounds
/// which scopes are meaningful there, so a token minted for one service can never carry scopes intended
/// for another.
/// </summary>
public sealed record DownstreamService(string Audience, IReadOnlySet<string> AllowedScopes);

/// <summary>Registry of valid token audiences. A minted token is always bound to exactly one entry here.</summary>
public interface IDownstreamRegistry
{
    DownstreamService? Get(string audience);
}
