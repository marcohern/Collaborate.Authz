using System.Net;
using System.Text;
using System.Text.Json;
using Collaborate.Authz.Exceptions;
using Collaborate.Authz.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Collaborate.Authz.Tests;

/// <summary>
/// Exercises the error middleware directly rather than through the pipeline: the point of the component is
/// what it does with an exception, and a fake <see cref="RequestDelegate"/> is the only way to inject one
/// deterministically. Assertions read the response body as JSON, same as the token-exchange suite.
/// </summary>
public sealed class ErrorHandlingMiddlewareTests
{
    // --- Uncontrolled exception: JSON body, generic 500, no internals on the wire. ---
    [Fact]
    public async Task Unhandled_exception_becomes_generic_json_500_outside_development()
    {
        var (status, raw, body) = await InvokeAsync(
            _ => throw new InvalidOperationException("boom"),
            environment: "Production");

        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.Equal("server_error", body.GetProperty("error").GetString());
        Assert.Equal("An unexpected error occurred.", body.GetProperty("error_description").GetString());
        Assert.False(body.TryGetProperty("stack_trace", out _));

        // Nothing about the failure's shape leaks to the caller.
        Assert.DoesNotContain("boom", raw);
        Assert.DoesNotContain("InvalidOperationException", raw);
    }

    // --- Development trades secrecy for debuggability: type, message and trace are included. ---
    [Fact]
    public async Task Unhandled_exception_includes_detail_in_development()
    {
        var (status, _, body) = await InvokeAsync(
            _ => throw new InvalidOperationException("boom"),
            environment: "Development");

        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.Equal("server_error", body.GetProperty("error").GetString());
        Assert.Equal("InvalidOperationException: boom", body.GetProperty("error_description").GetString());
        Assert.Contains("InvalidOperationException", body.GetProperty("stack_trace").GetString()!);
    }

    // --- Backstop: a TokenExchangeException thrown outside the handler keeps its own code and status. ---
    [Fact]
    public async Task Token_exchange_exception_keeps_its_error_code_and_status()
    {
        var (status, _, body) = await InvokeAsync(
            _ => throw new TokenExchangeException("invalid_client", "unregistered actor", StatusCodes.Status401Unauthorized),
            environment: "Production");

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
        Assert.Equal("unregistered actor", body.GetProperty("error_description").GetString());
    }

    // --- A malformed request body is the caller's fault: 400 invalid_request, not 500. ---
    [Fact]
    public async Task Malformed_request_becomes_invalid_request()
    {
        var (status, _, body) = await InvokeAsync(
            _ => throw new BadHttpRequestException("unexpected end of request content"),
            environment: "Production");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    // --- Any other domain exception still lands in the RFC 6749 shape rather than a 500. ---
    [Fact]
    public async Task Authz_exception_becomes_invalid_request()
    {
        var (status, _, body) = await InvokeAsync(
            _ => throw new AuthzException("subject is not delegable"),
            environment: "Production");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
        Assert.Equal("subject is not delegable", body.GetProperty("error_description").GetString());
    }

    // --- The happy path must pass through untouched. ---
    [Fact]
    public async Task Successful_request_is_left_alone()
    {
        HttpContext context = NewContext();
        var middleware = new ErrorHandlingMiddleware(
            _ => Task.CompletedTask,
            NullLogger<ErrorHandlingMiddleware>.Instance,
            new StubEnvironment("Production"));

        await middleware.InvokeAsync(context);

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
        Assert.Null(context.Response.ContentType);
    }

    // --- Once the response is on the wire it cannot be rewritten; the exception propagates instead. ---
    [Fact]
    public async Task Exception_after_response_started_is_rethrown()
    {
        // DefaultHttpContext never flips HasStarted on its own, so the started response is faked at the
        // feature level — that flag is the only thing the middleware actually reads.
        var features = new FeatureCollection();
        features.Set<IHttpRequestFeature>(new HttpRequestFeature { Method = "POST", Path = "/oauth2/token" });
        features.Set<IHttpResponseFeature>(new StartedResponseFeature());
        features.Set<IHttpResponseBodyFeature>(new StreamResponseBodyFeature(new MemoryStream()));
        var context = new DefaultHttpContext(features);

        var middleware = new ErrorHandlingMiddleware(
            _ => throw new InvalidOperationException("too late"),
            NullLogger<ErrorHandlingMiddleware>.Instance,
            new StubEnvironment("Production"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));
        Assert.Equal("too late", ex.Message);
    }

    private static async Task<(HttpStatusCode Status, string Raw, JsonElement Body)> InvokeAsync(
        RequestDelegate next, string environment)
    {
        HttpContext context = NewContext();
        var middleware = new ErrorHandlingMiddleware(
            next,
            NullLogger<ErrorHandlingMiddleware>.Instance,
            new StubEnvironment(environment));

        await middleware.InvokeAsync(context);

        context.Response.Body.Position = 0;
        string raw = await new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEndAsync();
        using JsonDocument doc = JsonDocument.Parse(raw);
        return ((HttpStatusCode)context.Response.StatusCode, raw, doc.RootElement.Clone());
    }

    private static HttpContext NewContext()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/oauth2/token";
        context.Response.Body = new MemoryStream();
        return context;
    }

    /// <summary>A response that claims to be already on the wire.</summary>
    private sealed class StartedResponseFeature : HttpResponseFeature
    {
        public override bool HasStarted => true;
    }

    /// <summary>Minimal IHostEnvironment so the Development/Production branch can be driven from a test.</summary>
    private sealed class StubEnvironment : IHostEnvironment
    {
        public StubEnvironment(string environmentName) => EnvironmentName = environmentName;

        public string EnvironmentName { get; set; }
        public string ApplicationName { get; set; } = "Collaborate.Authz.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
