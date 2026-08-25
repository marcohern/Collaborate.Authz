using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Security.Claims;
using Collaborate.Authz.Security;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Middleware
{
    /// <summary>
    /// Authenticates a caller from the standard <c>Authorization: Bearer &lt;jwt&gt;</c> header and publishes the
    /// result as <see cref="HttpContext.User"/>.
    ///
    /// This is the consumption half of the loop the service already had the minting half of: tokens issued by
    /// <see cref="Controllers.Oauth2Controller"/> can now be presented back and verified. Validation itself is
    /// delegated to <see cref="InboundTokenValidator"/> — the one place in this service that owns
    /// <see cref="TokenValidationParameters"/> — so header-borne and body-borne tokens are judged by identical
    /// rules, and no crypto lives here.
    ///
    /// Enforcement is opt-in per endpoint via <see cref="RequireBearerTokenAttribute"/>, which means the
    /// middleware must be registered <em>after</em> routing; before it, <c>GetEndpoint()</c> is always null and
    /// every request would sail through unchecked.
    /// </summary>
    public sealed class BearerTokenMiddleware
    {
        private const string BearerScheme = "Bearer";

        /// <summary>RFC 6750 §3.1 error code for any credential this middleware refuses.</summary>
        private const string InvalidToken = "invalid_token";

        // Deliberately coarse: the caller learns that its credential was rejected, never why. Distinguishing
        // "expired" from "bad signature" from "wrong issuer" hands an attacker a probing oracle.
        private const string MissingHeaderDescription = "A Bearer token is required in the Authorization header.";
        private const string InvalidTokenDescription = "The access token is not valid.";

        private readonly RequestDelegate _next;
        private readonly InboundTokenValidator _validator;
        private readonly ILogger<BearerTokenMiddleware> _log;

        public BearerTokenMiddleware(
            RequestDelegate next,
            InboundTokenValidator validator,
            ILogger<BearerTokenMiddleware> log)
        {
            _next = next;
            _validator = validator;
            _log = log;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Unmarked endpoints — and anything routing could not resolve, which the 404 path handles — are
            // none of this middleware's business.
            if (context.GetEndpoint()?.Metadata.GetMetadata<RequireBearerTokenAttribute>() is null)
            {
                await _next(context);
                return;
            }

            if (!TryReadBearerToken(context.Request, out string? token))
            {
                await ChallengeAsync(context, MissingHeaderDescription);
                return;
            }

            TokenValidationResult result = await _validator.ValidateAsync(token);
            if (!result.IsValid)
            {
                // The reason stays server-side: useful in a log, an oracle on the wire.
                _log.LogDebug(
                    result.Exception,
                    "Rejected bearer token for {Method} {Path}.",
                    context.Request.Method,
                    context.Request.Path);

                await ChallengeAsync(context, InvalidTokenDescription);
                return;
            }

            // ClaimsIdentity (not the raw Claims dictionary) is the right currency here: HttpContext.User is a
            // ClaimsPrincipal, and downstream code expects FindFirst/IsInRole to work. Guards that need the
            // unmapped payload keep reading TokenValidationResult.Claims via Utilities.Claim.
            context.User = new ClaimsPrincipal(result.ClaimsIdentity);

            await _next(context);
        }

        /// <summary>
        /// Extracts the token from an <c>Authorization: Bearer &lt;token&gt;</c> header, or returns false if the
        /// header is absent, uses another scheme, or carries no credential.
        /// </summary>
        private static bool TryReadBearerToken(HttpRequest request, [NotNullWhen(true)] out string? token)
        {
            token = null;

            string? header = request.Headers.Authorization.ToString();
            if (string.IsNullOrWhiteSpace(header))
                return false;

            if (!AuthenticationHeaderValue.TryParse(header, out AuthenticationHeaderValue? parsed))
                return false;

            // RFC 7235 declares the scheme case-insensitive; "bearer" from a hand-rolled client is legal.
            if (!string.Equals(parsed.Scheme, BearerScheme, StringComparison.OrdinalIgnoreCase))
                return false;

            if (string.IsNullOrWhiteSpace(parsed.Parameter))
                return false;

            token = parsed.Parameter;
            return true;
        }

        /// <summary>
        /// Writes the RFC 6750 challenge plus the RFC 6749 error body this service uses everywhere else.
        ///
        /// The response is written directly rather than by throwing for <see cref="ErrorHandlingMiddleware"/>
        /// to render: middleware owns its response, and going through the exception path would make this
        /// component's status code depend on that one's mapping table.
        /// </summary>
        private static async Task ChallengeAsync(HttpContext context, string description)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.WWWAuthenticate = $"{BearerScheme} error=\"{InvalidToken}\"";
            context.Response.ContentType = "application/json; charset=utf-8";

            await context.Response.WriteAsJsonAsync(new
            {
                error = InvalidToken,
                error_description = description,
            });
        }
    }
}
