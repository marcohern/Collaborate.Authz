using Collaborate.Authz.Responses;
using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Collaborate.Authz.Utilities;
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

        private readonly TokenDescriptorCreator _tokenDescriptorCreator;

        public Oauth2Controller(
            TokenExchangeHandler handler,
            JsonWebTokenHandler jwst,
            SigningKeyProvider keys,
            TokenDescriptorCreator tokenDescriptorCreator)
        {
            _handler = handler;
            _jwst = jwst;
            _keys = keys;
            _tokenDescriptorCreator = tokenDescriptorCreator;
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
                var accessDescriptor = _tokenDescriptorCreator.CreateAccessTokenDescriptor(login.Username, "Administrator", _keys.SigningCredentials);
                var refreshDescriptor = _tokenDescriptorCreator.CreateRefreshTokenDescriptor(login.Username, "Administrator", _keys.SigningCredentials);

                var accessToken = _jwst.CreateToken(accessDescriptor);
                var refreshToken = _jwst.CreateToken(refreshDescriptor);

                return new TokenResponse
                {
                    AccessToken = accessToken,
                    Expires = DateTime.UtcNow.AddHours(24),
                    RefreshToken = refreshToken,
                    Scope = "pet.read pet.write",
                };
            }
            else
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }
        }
    }
}
