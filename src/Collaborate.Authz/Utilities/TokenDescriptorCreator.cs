using Collaborate.Authz.TokenExchange;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Utilities
{
    public class TokenDescriptorCreator
    {
        public SecurityTokenDescriptor CreateAccessTokenDescriptor(string username, string name, SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Issuer = TokenConstants.Issuer,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddHours(24),
                SigningCredentials = signingCredentials,
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = "access",
                    ["auth_version"] = 1,
                    ["username"] = username,
                    ["name"] = name,
                },
            };
        }

        public SecurityTokenDescriptor CreateRefreshTokenDescriptor(string username, string name, SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Issuer = TokenConstants.Issuer,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(30),
                SigningCredentials = signingCredentials,
                Claims = new Dictionary<string, object>
                {
                    ["sub"] = "refresh",
                    ["auth_version"] = 1,
                    ["username"] = username,
                    ["name"] = name,
                },
            };
        }
    }
}
