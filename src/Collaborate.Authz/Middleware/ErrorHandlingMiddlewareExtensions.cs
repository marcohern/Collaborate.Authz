namespace Collaborate.Authz.Middleware
{
    public static class ErrorHandlingMiddlewareExtensions
    {
        /// <summary>
        /// Registers <see cref="ErrorHandlingMiddleware"/>. Call it first, so it wraps routing, model
        /// binding and endpoint execution alike.
        /// </summary>
        public static IApplicationBuilder UseJsonErrorHandling(this IApplicationBuilder app) =>
            app.UseMiddleware<ErrorHandlingMiddleware>();
    }
}
