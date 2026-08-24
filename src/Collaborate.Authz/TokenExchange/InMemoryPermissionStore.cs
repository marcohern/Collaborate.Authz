using System.Collections.Concurrent;

namespace Collaborate.Authz.TokenExchange;

/// <summary>
/// Stub PDP with a couple of seeded users. Stands in for the Redis-backed permission cache so the
/// slice is runnable and testable without external infrastructure.
/// </summary>
public sealed class InMemoryPermissionStore : IPermissionStore
{
    private readonly ConcurrentDictionary<string, UserPermissions> _users = new(StringComparer.Ordinal);

    public InMemoryPermissionStore()
    {
        Seed(new UserPermissions("emp-1", "firm-a", "ws-1", "contributor",
            new HashSet<string>(StringComparer.Ordinal) { "doc.read", "comment.read" }, AuthVersion: 1));

        // A user in a different firm — used to prove an actor cannot act across firm boundaries.
        Seed(new UserPermissions("emp-2", "firm-b", "ws-2", "viewer",
            new HashSet<string>(StringComparer.Ordinal) { "doc.read" }, AuthVersion: 1));
    }

    private void Seed(UserPermissions user) => _users[user.UserId] = user;

    public UserPermissions? Get(string userId) =>
        _users.TryGetValue(userId, out var user) ? user : null;

    public void BumpAuthVersion(string userId)
    {
        _users.AddOrUpdate(
            userId,
            _ => throw new KeyNotFoundException(userId),
            (_, existing) => existing with { AuthVersion = existing.AuthVersion + 1 });
    }
}
