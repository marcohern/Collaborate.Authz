namespace Collaborate.Authz.Middleware
{
    /// <summary>
    /// Opt-in marker for <see cref="BearerTokenMiddleware"/>. An endpoint without it is anonymous — the
    /// middleware passes the request straight through.
    ///
    /// Opt-in rather than opt-out because the two endpoints that matter here must stay anonymous by
    /// definition: the login endpoint has no token yet, and RFC 8693 token exchange carries its credentials
    /// in the form body, not the <c>Authorization</c> header.
    ///
    /// On a controller or action the attribute reaches endpoint metadata on its own; a minimal-API endpoint
    /// opts in with <c>.WithMetadata(new RequireBearerTokenAttribute())</c>.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public sealed class RequireBearerTokenAttribute : Attribute;
}
