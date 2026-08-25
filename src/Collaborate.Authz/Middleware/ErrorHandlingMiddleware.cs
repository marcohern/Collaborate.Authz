using Collaborate.Authz.Exceptions;

namespace Collaborate.Authz.Middleware
{
    /// <summary>
    /// Terminal safety net at the outermost edge of the pipeline. Every deliberate failure in this service
    /// already answers with the RFC 6749 shape (<c>{ error, error_description }</c>) via
    /// <see cref="Utilities.JsonResults"/>; this middleware guarantees the same for anything uncontrolled,
    /// so a client never sees an HTML developer page or an empty 500 body.
    ///
    /// It is not the primary error path — the token-exchange guards catch their own
    /// <see cref="TokenExchangeException"/> so each guard keeps its 1:1 test. The catch below is a backstop
    /// for the ones thrown outside that try (e.g. during form reading).
    /// </summary>
    public sealed class ErrorHandlingMiddleware
    {
        private const string GenericDescription = "An unexpected error occurred.";

        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _log;
        private readonly IHostEnvironment _env;

        public ErrorHandlingMiddleware(
            RequestDelegate next,
            ILogger<ErrorHandlingMiddleware> log,
            IHostEnvironment env)
        {
            _next = next;
            _log = log;
            _env = env;
        }

        public async Task RenderExceptionAsync(Exception ex, HttpContext context)
        {
            int statusCode = ComputeStatusCode(ex);
            _log.LogError(ex, ex.Message, context.Request.Method, context.Request.Path);
            if (!await TryWriteAsync(context, "server_error", ex.Message, statusCode, ex.StackTrace))
                throw ex;
        }

        private int ComputeStatusCode(Exception ex)
        {
            if (ex is AuthzException)
                return StatusCodes.Status400BadRequest;
            else if (ex is UnauthorizedAccessException)
                return StatusCodes.Status401Unauthorized;
            else
                return StatusCodes.Status500InternalServerError;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await RenderExceptionAsync(ex, context);
            }
        }

        /// <summary>
        /// Writes the RFC 6749 error shape, or returns false if the response is already on the wire and can
        /// no longer be rewritten. Mirrors <see cref="Utilities.JsonResults.Error"/>, which returns an
        /// <see cref="IResult"/> — the wrong currency inside middleware, where we own the response directly.
        /// </summary>
        private static async Task<bool> TryWriteAsync(
            HttpContext context,
            string error,
            string description,
            int statusCode,
            string? stackTrace = null)
        {
            // Once bytes are on the wire, appending an error document would only corrupt the body; the
            // caller re-throws so the server aborts the connection instead.
            if (context.Response.HasStarted)
                return false;

            context.Response.Clear();
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json; charset=utf-8";

            if (stackTrace is null)
            {
                await context.Response.WriteAsJsonAsync(new
                {
                    error,
                    error_description = description,
                });
            }
            else
            {
                await context.Response.WriteAsJsonAsync(new
                {
                    error,
                    error_description = description,
                    stack_trace = stackTrace,
                });
            }

            return true;
        }
    }
}
