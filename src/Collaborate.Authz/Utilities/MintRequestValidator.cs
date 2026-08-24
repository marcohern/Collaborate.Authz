using Collaborate.Authz.Exceptions;
using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Microsoft.AspNetCore.Http;
using System.Security;
using System.Threading.Tasks;

namespace Collaborate.Authz.Utilities
{
    public class MintRequestValidator
    {
        private readonly InboundTokenValidator _validator;
        private readonly IPermissionStore _permissions;
        private readonly IActorTrustPolicy _actors;
        private readonly IDownstreamRegistry _downstreams;

        public MintRequestValidator(
            InboundTokenValidator validator,
            IPermissionStore permissions,
            IActorTrustPolicy actors,
            IDownstreamRegistry downstreams)
        {
            _validator = validator;
            _permissions = permissions;
            _actors = actors;
            _downstreams = downstreams;
        }

        /// <summary>
        /// Validates the incoming token exchange request form data.
        /// </summary>
        /// <param name="form">Form Body from HTTP Request</param>
        /// <exception cref="TokenExchangeException">Thrown when validation fails.</exception>
        public async Task<MintRequest> Validate(IFormCollection form)
        {
            if (!form.TryGetValue("grant_type", out var grantType) || string.IsNullOrWhiteSpace(grantType))
            {
                throw new TokenExchangeException("unsupported_grant_type", $"grant_type must be {TokenConstants.GrantType}", StatusCodes.Status400BadRequest);
            }
            if (!form.TryGetValue("subject_token", out var subjectToken) || string.IsNullOrWhiteSpace(subjectToken))
            {
                throw new TokenExchangeException("invalid_request", "subject_token is required", StatusCodes.Status400BadRequest);
            }
            if (!form.TryGetValue("actor_token", out var actorToken) || string.IsNullOrWhiteSpace(actorToken))
            {
                throw new TokenExchangeException("invalid_request", "actor_token is required for delegation", StatusCodes.Status400BadRequest);
            }
            if (!form.TryGetValue("audience", out var audience) || string.IsNullOrWhiteSpace(audience))
            {
                throw new TokenExchangeException("invalid_target", "audience is required; refusing to mint an unrestricted token", StatusCodes.Status400BadRequest);
            }
            
            var subjectResult = await _validator.ValidateAsync(subjectToken.ToString());
            if (!subjectResult.IsValid)
                throw new TokenExchangeException("invalid_request", "subject_token is invalid or expired", StatusCodes.Status400BadRequest);

            var actorResult = await _validator.ValidateAsync(actorToken.ToString());
            if (!actorResult.IsValid)
                throw new TokenExchangeException("invalid_client", "actor_token is invalid or expired", StatusCodes.Status401Unauthorized);

            string? subjectId = Claim.String(subjectResult, "sub");
            string? actorId = Claim.String(actorResult, "sub");
            if (subjectId is null || actorId is null)
                throw new TokenExchangeException("invalid_request", "subject_token and actor_token must both carry a sub claim", StatusCodes.Status400BadRequest);

            var perms = _permissions.Get(subjectId);
            if (perms is null)
                throw new TokenExchangeException("invalid_grant", "subject has no permissions in this tenant", StatusCodes.Status400BadRequest);

            if (Claim.Int(subjectResult, "auth_version") is int presented && presented < perms.AuthVersion)
                throw new TokenExchangeException("invalid_grant", "subject authorization was revoked or changed; re-authenticate", StatusCodes.Status400BadRequest);

            var actor = _actors.Resolve(actorId);
            if (actor is null)
                throw new TokenExchangeException("invalid_client", "actor is not a registered delegation client", StatusCodes.Status401Unauthorized);
            if (!string.Equals(actor.FirmId, perms.FirmId, StringComparison.Ordinal))
                throw new TokenExchangeException("unauthorized_client", "actor is not permitted to act for the subject's firm", StatusCodes.Status403Forbidden);

            var downstream = _downstreams.Get(audience.ToString());
            if (downstream is null)
                throw new TokenExchangeException("invalid_target", $"unknown audience '{audience}'", StatusCodes.Status400BadRequest);

            IReadOnlyCollection<string> requested = Scopes.Parse(form["scope"].ToString());
            var granted = GrantedScopes.Compute(requested, perms.Scopes, actor.DelegatableScopes, downstream.AllowedScopes);
            if (granted.Count == 0)
                throw new TokenExchangeException("invalid_scope", "no scopes remain after downscoping to subject/actor/audience", StatusCodes.Status400BadRequest);

            return new MintRequest(
                Subject: subjectId,
                Actor: actorId,
                Audience: audience.ToString(),
                FirmId: perms.FirmId,
                WorkspaceId: perms.WorkspaceId,
                Scopes: granted,
                AuthVersion: perms.AuthVersion);
        }
    }
}
