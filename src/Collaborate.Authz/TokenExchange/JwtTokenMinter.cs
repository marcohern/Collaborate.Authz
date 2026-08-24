using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Collaborate.Authz.Security;

namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// Issues the narrowed, downstream-scoped access token. Uses the framework's
/// <see cref="JsonWebTokenHandler"/> and <see cref="SecurityTokenDescriptor"/> to build and RS256-sign
/// the JWT — we supply claims and a signing key, the library does the cryptography.
///
/// The token encodes the delegation explicitly:
///   sub          = the end user being acted for (attribution + downstream authorization)
///   act.sub      = the acting party (RFC 8693 actor claim — audit chain, "who is the deputy")
///   aud          = exactly one downstream (confused-deputy guard: not replayable elsewhere)
///   scope        = the intersection-narrowed grant (least privilege)
///   auth_version = the revocation epoch (downstream/gateway rejects stale versions)
/// </summary>
public sealed class JwtTokenMinter : ITokenMinter
{
    private const int LifetimeSeconds = 120;

    private readonly SigningKeyProvider _keys;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtTokenMinter(SigningKeyProvider keys) => _keys = keys;

    public MintedToken Mint(MintRequest request)
    {
        string scope = string.Join(' ', request.Scopes);
        DateTime now = DateTime.UtcNow;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = TokenConstants.Issuer,
            Audience = request.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(LifetimeSeconds),
            SigningCredentials = _keys.SigningCredentials,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = request.Subject,
                ["client_id"] = request.Actor,
                ["scope"] = scope,
                ["firm"] = request.FirmId,
                ["workspace"] = request.WorkspaceId,
                ["auth_version"] = request.AuthVersion,
                // RFC 8693 actor claim: a nested object naming the delegate. Preserves the "on behalf of"
                // chain so the downstream call stays attributable to the acting party for audit.
                ["act"] = new Dictionary<string, object> { ["sub"] = request.Actor },
            },
        };

        string jwt = _handler.CreateToken(descriptor);
        return new MintedToken(jwt, LifetimeSeconds, scope);
    }
}
