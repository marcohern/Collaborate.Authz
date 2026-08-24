namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// A registered delegation client (the "actor" acting on behalf of a user). Its <see cref="FirmId"/>
/// scopes which users it may act for, and <see cref="DelegatableScopes"/> caps what it may ever request
/// regardless of the subject's own permissions. This is the registration that makes confused-deputy
/// attacks impossible: an actor can never exceed both its own grant and the subject's permissions.
/// </summary>
public sealed record ActorGrant(
    string ActorId,
    string FirmId,
    IReadOnlySet<string> DelegatableScopes);

/// <summary>Resolves and authorizes the acting party in an on-behalf-of exchange.</summary>
public interface IActorTrustPolicy
{
    /// <summary>Returns the actor's registration, or null if the actor is unknown / not permitted to delegate.</summary>
    ActorGrant? Resolve(string actorId);
}
