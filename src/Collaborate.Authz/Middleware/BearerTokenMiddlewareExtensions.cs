namespace Collaborate.Authz.Middleware
{
    public static class BearerTokenMiddlewareExtensions
    {
        /// <summary>
        /// Registers <see cref="BearerTokenMiddleware"/>. Call it after <c>UseRouting</c> and before the
        /// endpoints — it reads <see cref="RequireBearerTokenAttribute"/> off the matched endpoint's metadata,
        /// which routing has not populated yet any earlier.
        /// </summary>
        public static IApplicationBuilder UseBearerTokenValidation(this IApplicationBuilder app) =>
            app.UseMiddleware<BearerTokenMiddleware>();
    }
}
