using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Collaborate.Authz.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;
using System.Security;

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
        public async Task<IResult> LoginAsync([FromBody] PasswordLogin login)
        {
            await Task.CompletedTask;
            if (login.Username == "admin" && login.Password == "Admin123")
            {
                var descriptor = new SecurityTokenDescriptor
                {
                    Issuer = TokenConstants.Issuer,
                    IssuedAt = DateTime.Now,
                    NotBefore = DateTime.Now,
                    Expires = DateTime.Now.AddHours(24),
                    SigningCredentials = _keys.SigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        ["sub"] = "user",
                        ["auth_version"] = 1,
                        ["username"] = login.Username,
                        ["name"] = "Administrator",
                    },
                };
                var token = _jwst.CreateToken(descriptor);

                return Results.Json(new
                {
                    Token = token
                });
            }
            else
            {
                return Results.Unauthorized();
            }
        }
    }
}
