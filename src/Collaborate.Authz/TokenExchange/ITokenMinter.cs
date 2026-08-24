namespace Collaborate.Authz.TokenExchange;

/// <summary>Everything the minter needs to issue one downstream-scoped access token.</summary>
public sealed record MintRequest(
    string Subject,
    string Actor,
    string Audience,
    string FirmId,
    string WorkspaceId,
    IReadOnlyCollection<string> Scopes,
    int AuthVersion);

/// <summary>The compact JWT plus the metadata RFC 8693 requires in the token response.</summary>
public sealed record MintedToken(string AccessToken, int ExpiresInSeconds, string Scope);

public interface ITokenMinter
{
    MintedToken Mint(MintRequest request);
}
