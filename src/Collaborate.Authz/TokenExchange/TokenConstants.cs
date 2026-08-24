namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// RFC 8693 (OAuth 2.0 Token Exchange) identifiers plus this authorization server's own issuer.
/// Kept in one place so the wire contract is unambiguous and testable.
/// </summary>
public static class TokenConstants
{
    /// <summary>Issuer of every token this service mints, and the trusted issuer of inbound subject/actor tokens.</summary>
    public const string Issuer = "https://authz.collaborate.local";

    /// <summary>RFC 8693 grant_type for token exchange.</summary>
    public const string GrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>RFC 8693 token type URN for a JWT presented as subject_token / actor_token.</summary>
    public const string JwtTokenType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>RFC 8693 token type URN returned in issued_token_type for an access token.</summary>
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
}
