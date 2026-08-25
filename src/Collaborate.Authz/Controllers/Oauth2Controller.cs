using Collaborate.Authz.Responses;
using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Oauth2Controller : ControllerBase
    {
        private readonly TokenExchangeHandler _handler;
        private readonly JsonWebTokenHandler _jwst;
        private readonly SigningKeyProvider _keys;

        public Oauth2Controller(
            TokenExchangeHandler handler,
            JsonWebTokenHandler jwst,
            SigningKeyProvider keys)
        {
            _handler = handler;
            _jwst = jwst;
            _keys = keys;
        }

        [HttpPost]
        [Route("create-token")]
        public async Task<IResult> TokenAsync()
        {
            return await _handler.HandleAsync(Request);
        }

        [HttpPost]
        [Route("token")]
        public async Task<TokenResponse> LoginAsync([FromBody] PasswordLogin login)
        {
            await Task.CompletedTask;
            if (login.Username == "admin" && login.Password == "Admin123")
            {
                var accessDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = TokenConstants.Issuer,
                    IssuedAt = DateTime.Now,
                    NotBefore = DateTime.Now,
                    Expires = DateTime.Now.AddHours(24),
                    SigningCredentials = _keys.SigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        ["sub"] = "access",
                        ["auth_version"] = 1,
                        ["username"] = login.Username,
                        ["name"] = "Administrator",
                    },
                };
                var refreshDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = TokenConstants.Issuer,
                    IssuedAt = DateTime.Now,
                    NotBefore = DateTime.Now,
                    Expires = DateTime.Now.AddDays(30),
                    SigningCredentials = _keys.SigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        ["sub"] = "refreshToken",
                        ["auth_version"] = 1,
                        ["username"] = login.Username,
                        ["name"] = "Administrator",
                    },
                };

                var accessToken = _jwst.CreateToken(accessDescriptor);
                var refreshToken = _jwst.CreateToken(refreshDescriptor);

                return new TokenResponse
                {
                    AccessToken = accessToken,
                    Expires = DateTime.Now.AddHours(24),
                    RefreshToken = refreshToken,
                };
            }
            else
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }
        }
    }
}
