using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Collaborate.Authz.TokenExchange;

namespace Collaborate.Authz.Security;

/// <summary>
/// Validates inbound subject_token / actor_token JWTs.
///
/// We deliberately use <see cref="JsonWebTokenHandler"/> directly rather than the JwtBearer middleware:
/// in a token-exchange request the tokens arrive in the form body (RFC 8693), not the Authorization
/// header, so the [Authorize] pipeline is the wrong tool. We still lean entirely on the framework for
/// signature verification, issuer, and lifetime validation — no custom crypto or parsing.
/// </summary>
public sealed class InboundTokenValidator
{
    private readonly TokenValidationParameters _parameters;
    private readonly JsonWebTokenHandler _handler = new();

    public InboundTokenValidator(SigningKeyProvider keys)
    {
        _parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = TokenConstants.Issuer,
            // The exchange's target audience is validated separately (against the downstream registry);
            // subject/actor tokens are identity assertions and are not audience-restricted to this endpoint.
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = keys.SecurityKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    }

    public Task<TokenValidationResult> ValidateAsync(string token) =>
        _handler.ValidateTokenAsync(token, _parameters);
}
