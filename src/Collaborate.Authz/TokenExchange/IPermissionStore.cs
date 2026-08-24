namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// A user's authorization snapshot as held by the Policy Decision Point (PDP).
/// In production this is a per-user record in Redis, refreshed by permissions-DB change events
/// (see DESIGN.md). <see cref="AuthVersion"/> is the revocation epoch: bumping it invalidates
/// previously-issued tokens without waiting for them to expire.
/// </summary>
public sealed record UserPermissions(
    string UserId,
    string FirmId,
    string WorkspaceId,
    string Role,
    IReadOnlySet<string> Scopes,
    int AuthVersion);

/// <summary>
/// Source of truth for what a subject is allowed to do. The token-exchange endpoint reads from this
/// (never trusts scopes claimed by the caller), which is what makes the exchange safe.
/// The interface is intentionally Redis-shaped so the in-memory stub can be swapped for ElastiCache.
/// </summary>
public interface IPermissionStore
{
    UserPermissions? Get(string userId);

    /// <summary>Advance the revocation epoch for a user (models a permission/membership change event).</summary>
    void BumpAuthVersion(string userId);
}
