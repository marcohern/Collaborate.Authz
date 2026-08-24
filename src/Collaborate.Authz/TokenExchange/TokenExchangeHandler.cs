using Collaborate.Authz.Exceptions;
using Collaborate.Authz.Security;
using Collaborate.Authz.Utilities;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// Handles POST /oauth2/token for the RFC 8693 token-exchange grant.
///
/// The whole point of this endpoint is to turn "I am service X and here is user U's identity" into a
/// narrow, audience-bound token that lets X call one downstream as U — without X being able to escalate.
/// The checks below run in order; each is a confused-deputy / least-privilege guard and each maps to a
/// test in TokenExchangeTests.
/// </summary>
public sealed class TokenExchangeHandler
{
    
    private readonly ITokenMinter _minter;
    private readonly MintRequestValidator _mintVaildator;
    private readonly ILogger<TokenExchangeHandler> _log;

    public TokenExchangeHandler(
        MintRequestValidator mintValidator,
        ITokenMinter minter,
        ILogger<TokenExchangeHandler> log)
    {
        _mintVaildator = mintValidator;
        _minter = minter;
        _log = log;
    }

    public async Task<IResult> HandleAsync(HttpRequest request)
    {
        if (!request.HasFormContentType)
            return JsonResults.Error("invalid_request", "expected application/x-www-form-urlencoded", StatusCodes.Status400BadRequest);
        var form = await request.ReadFormAsync();
        try
        {
            var mintRequest = await _mintVaildator.Validate(form);
            var minted = _minter.Mint(mintRequest);

            _log.LogInformation(
                "token-exchange granted sub={Subject} act={Actor} aud={Audience} scope=\"{Scope}\" firm={Firm}",
                mintRequest.Subject, mintRequest.Actor, mintRequest.Audience, minted.Scope, mintRequest.FirmId);

            return Results.Json(new
            {
                access_token = minted.AccessToken,
                issued_token_type = TokenConstants.AccessTokenType,
                token_type = "Bearer",
                expires_in = minted.ExpiresInSeconds,
                scope = minted.Scope,
            });
        }
        catch (TokenExchangeException ex)
        {
            return JsonResults.Error(ex.ErrorType, ex.Message, ex.StatusCode);
        }

        
    }
}
