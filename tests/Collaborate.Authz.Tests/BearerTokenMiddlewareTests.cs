using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Collaborate.Authz.Tests;

/// <summary>
/// Exercises <c>BearerTokenMiddleware</c> end-to-end over the real pipeline, the way the token-exchange suite
/// does: the interesting behavior is where the middleware sits relative to routing and endpoint metadata, and
/// only a booted app reproduces that. <c>GET /api/me</c> (minimal API) and <c>GET /api/PrivateValues</c>
/// (controller, attribute on the class) are the marked endpoints; the login endpoint is the unmarked control
/// that proves enforcement is opt-in.
///
/// Tokens are signed with the app's own <see cref="SigningKeyProvider"/> singleton resolved from
/// <c>_factory.Services</c>, so the same key that validates them issued them — no real IdP in the loop.
/// </summary>
public sealed class BearerTokenMiddlewareTests : IDisposable
{
    private const string ProtectedPath = "/api/me";

    /// <summary>A marked <em>controller</em> endpoint: the attribute sits on the class, not the action.</summary>
    private const string ProtectedControllerPath = "/api/PrivateValues";

    private readonly WebApplicationFactory<Program> _factory = new();
    private readonly HttpClient _client;
    private readonly SigningKeyProvider _keys;

    public BearerTokenMiddlewareTests()
    {
        _client = _factory.CreateClient();
        _keys = _factory.Services.GetRequiredService<SigningKeyProvider>();
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // --- No credential at all: 401 plus the RFC 6750 challenge telling the client what to present. ---
    [Fact]
    public async Task Missing_authorization_header_is_challenged()
    {
        HttpResponseMessage response = await _client.GetAsync(ProtectedPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());

        JsonElement body = await ReadBodyAsync(response);
        Assert.Equal("invalid_token", body.GetProperty("error").GetString());
    }

    // --- Another auth scheme is not a bearer token, however well-formed it is. ---
    [Fact]
    public async Task Non_bearer_scheme_is_rejected()
    {
        HttpResponseMessage response = await GetWithRawAuthorizationAsync("Basic YWRtaW46QWRtaW4xMjM=");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- The scheme is case-insensitive per RFC 7235; a lowercase client must still work. ---
    [Fact]
    public async Task Bearer_scheme_is_case_insensitive()
    {
        string token = TestTokens.Identity(_keys, subject: "user-casing");

        HttpResponseMessage response = await GetWithRawAuthorizationAsync($"bearer {token}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // --- Right scheme, no credential: still nothing to validate. ---
    [Fact]
    public async Task Bearer_scheme_without_a_token_is_rejected()
    {
        HttpResponseMessage response = await GetWithRawAuthorizationAsync("Bearer ");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- Garbage that is not a JWT must fail as a 401, not as an unhandled parse exception / 500. ---
    [Fact]
    public async Task Malformed_token_is_rejected()
    {
        HttpResponseMessage response = await GetWithRawAuthorizationAsync("Bearer not-a-jwt");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- Lifetime is enforced: a well-signed but expired token buys nothing. ---
    [Fact]
    public async Task Expired_token_is_rejected()
    {
        string token = TestTokens.ExpiredIdentity(_keys, subject: "user-expired");

        HttpResponseMessage response = await GetWithBearerAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- The signature is the trust anchor: a structurally perfect token from a foreign key is refused. ---
    [Fact]
    public async Task Token_signed_by_a_foreign_key_is_rejected()
    {
        // A second SigningKeyProvider would NOT be foreign: it loads the same fixed dev-signing-key.pem that
        // is copied into the test output. The impostor key has to be generated outright.
        using RSA impostor = RSA.Create(2048);
        var credentials = new SigningCredentials(
            new RsaSecurityKey(impostor) { KeyId = "impostor-key" },
            SecurityAlgorithms.RsaSha256);

        DateTime now = DateTime.UtcNow;
        string token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = TokenConstants.Issuer,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            SigningCredentials = credentials,
            Claims = new Dictionary<string, object> { ["sub"] = "user-impostor" },
        });

        HttpResponseMessage response = await GetWithBearerAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- Happy path: the request reaches the endpoint and HttpContext.User carries the token's claims. ---
    [Fact]
    public async Task Valid_token_is_accepted_and_populates_the_principal()
    {
        string token = TestTokens.Identity(_keys, subject: "user-42");

        HttpResponseMessage response = await GetWithBearerAsync(token);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The endpoint echoes ctx.User.FindFirst("sub"), so this asserts the principal, not just the status.
        JsonElement body = await ReadBodyAsync(response);
        Assert.Equal("user-42", body.GetProperty("sub").GetString());
    }

    // --- The gate is opt-in: an unmarked endpoint is untouched by the middleware. ---
    [Fact]
    public async Task Unmarked_endpoint_is_reachable_without_a_token()
    {
        HttpResponseMessage response = await _client.PostAsJsonAsync(
            "/oauth2/login",
            new { username = "admin", password = "Admin123" });

        // The login endpoint answers on its own terms; what matters is that the middleware did not challenge.
        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- The gate also covers controllers: [RequireBearerToken] on the class reaches endpoint metadata. ---
    [Fact]
    public async Task Marked_controller_endpoint_is_challenged_without_a_token()
    {
        HttpResponseMessage response = await _client.GetAsync(ProtectedControllerPath);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Bearer", response.Headers.WwwAuthenticate.ToString());

        JsonElement body = await ReadBodyAsync(response);
        Assert.Equal("invalid_token", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Marked_controller_endpoint_is_reachable_with_a_valid_token()
    {
        string token = TestTokens.Identity(_keys, subject: "user-42");

        HttpResponseMessage response = await GetWithBearerAsync(token, ProtectedControllerPath);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        JsonElement body = await ReadBodyAsync(response);
        Assert.Equal(3, body.GetArrayLength());
    }

    private Task<HttpResponseMessage> GetWithBearerAsync(string token, string path = ProtectedPath)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return _client.SendAsync(request);
    }

    /// <summary>
    /// Sends a verbatim Authorization header. <see cref="AuthenticationHeaderValue"/> refuses to model the
    /// malformed cases these tests exist to cover, so the header is set without validation.
    /// </summary>
    private Task<HttpResponseMessage> GetWithRawAuthorizationAsync(string headerValue)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, ProtectedPath);
        request.Headers.TryAddWithoutValidation("Authorization", headerValue);
        return _client.SendAsync(request);
    }

    private static async Task<JsonElement> ReadBodyAsync(HttpResponseMessage response)
    {
        using JsonDocument doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.Clone();
    }
}
