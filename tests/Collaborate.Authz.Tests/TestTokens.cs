using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Tests;

/// <summary>
/// Mints inbound subject/actor identity tokens for tests, signed with the same dev key the server uses
/// to validate them. Stands in for the central IdP / a client's identity assertion — no real IdP needed.
/// </summary>
internal static class TestTokens
{
    private static readonly JsonWebTokenHandler Handler = new();

    public static string Identity(SigningKeyProvider keys, string subject, int authVersion = 1, int lifetimeSeconds = 300)
    {
        DateTime now = DateTime.UtcNow;
        return Create(keys, subject, authVersion, notBefore: now, expires: now.AddSeconds(lifetimeSeconds));
    }

    public static string ExpiredIdentity(SigningKeyProvider keys, string subject, int authVersion = 1)
    {
        DateTime now = DateTime.UtcNow;
        // Expired well beyond the validator's 30s clock skew.
        return Create(keys, subject, authVersion, notBefore: now.AddSeconds(-300), expires: now.AddSeconds(-120));
    }

    private static string Create(SigningKeyProvider keys, string subject, int authVersion, DateTime notBefore, DateTime expires)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = TokenConstants.Issuer,
            IssuedAt = notBefore,
            NotBefore = notBefore,
            Expires = expires,
            SigningCredentials = keys.SigningCredentials,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = subject,
                ["auth_version"] = authVersion,
            },
        };
        return Handler.CreateToken(descriptor);
    }
}
