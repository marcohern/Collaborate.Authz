using System.Net;
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
/// End-to-end tests over the real ASP.NET Core pipeline (WebApplicationFactory). xUnit constructs a new
/// instance per test, so each test gets a fresh in-memory permission store — the revocation test can bump
/// state without leaking into the others.
/// </summary>
public sealed class TokenExchangeTests : IDisposable
{
    private readonly WebApplicationFactory<Program> _factory = new();
    private readonly HttpClient _client;
    private readonly SigningKeyProvider _keys;
    private readonly IPermissionStore _permissions;

    public TokenExchangeTests()
    {
        _client = _factory.CreateClient();
        _keys = _factory.Services.GetRequiredService<SigningKeyProvider>();
        _permissions = _factory.Services.GetRequiredService<IPermissionStore>();
    }

    // --- Happy path: a valid delegation mints a narrow, audience-bound, attributable token. ---
    [Fact]
    public async Task Valid_delegation_mints_narrow_token_with_actor_claim()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal(TokenConstants.AccessTokenType, body.GetProperty("issued_token_type").GetString());
        Assert.Equal("doc.read", body.GetProperty("scope").GetString());

        JsonWebToken minted = await ValidateMintedAsync(body.GetProperty("access_token").GetString()!, audience: "DocumentService");
        Assert.Equal("emp-1", minted.GetPayloadValue<string>("sub"));
        Assert.Equal("doc.read", minted.GetPayloadValue<string>("scope"));
        Assert.Equal("firm-a", minted.GetPayloadValue<string>("firm"));
        Assert.Equal(1, minted.GetPayloadValue<int>("auth_version"));

        // RFC 8693 actor claim carries the delegate for audit attribution.
        Assert.True(minted.TryGetPayloadValue("act", out JsonElement act));
        Assert.Equal("client-sys-a", act.GetProperty("sub").GetString());
    }

    // --- Downscoping: caller asks for more than the subject has; grant is the intersection only. ---
    [Fact]
    public async Task Requested_scope_is_downscoped_to_subject_permissions()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "DocumentService",
            scope: "doc.read doc.write"); // emp-1 only has doc.read

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("doc.read", body.GetProperty("scope").GetString());
    }

    // --- Confused-deputy guard: no audience => refuse to mint an unrestricted token. ---
    [Fact]
    public async Task Missing_audience_is_rejected_as_invalid_target()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: null,
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_target", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Unknown_audience_is_rejected_as_invalid_target()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "GhostService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_target", body.GetProperty("error").GetString());
    }

    // --- Scope escalation with no legitimate overlap => nothing is granted. ---
    [Fact]
    public async Task Scope_with_empty_intersection_is_rejected_as_invalid_scope()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "CommentsService",
            scope: "comment.write"); // neither the subject nor the actor holds this

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    // --- Cross-firm delegation is refused: firm-a's client cannot act for a firm-b user. ---
    [Fact]
    public async Task Actor_cannot_act_for_a_subject_in_another_firm()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-2"),      // firm-b
            actor: TestTokens.Identity(_keys, "client-sys-a"), // firm-a
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Equal("unauthorized_client", body.GetProperty("error").GetString());
    }

    // --- Unregistered actor cannot delegate at all. ---
    [Fact]
    public async Task Unregistered_actor_is_rejected_as_invalid_client()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-unknown"),
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("invalid_client", body.GetProperty("error").GetString());
    }

    // --- A cryptographically valid but expired subject token is refused. ---
    [Fact]
    public async Task Expired_subject_token_is_rejected()
    {
        var (status, body) = await ExchangeAsync(
            subject: TestTokens.ExpiredIdentity(_keys, "emp-1"),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_request", body.GetProperty("error").GetString());
    }

    // --- Revocation: bumping the epoch invalidates a still-signed-and-unexpired identity within seconds. ---
    [Fact]
    public async Task Revoked_subject_epoch_rejects_stale_identity_but_accepts_refreshed_one()
    {
        // A user logs in (epoch 1), then their access is revoked/changed => epoch advances to 2.
        string staleIdentity = TestTokens.Identity(_keys, "emp-1", authVersion: 1);
        _permissions.BumpAuthVersion("emp-1");

        var (staleStatus, staleBody) = await ExchangeAsync(
            subject: staleIdentity,
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.BadRequest, staleStatus);
        Assert.Equal("invalid_grant", staleBody.GetProperty("error").GetString());

        // After re-authentication the user presents a fresh identity at the new epoch and succeeds;
        // the minted token carries the new version so downstreams see the current epoch.
        var (freshStatus, freshBody) = await ExchangeAsync(
            subject: TestTokens.Identity(_keys, "emp-1", authVersion: 2),
            actor: TestTokens.Identity(_keys, "client-sys-a"),
            audience: "DocumentService",
            scope: "doc.read");

        Assert.Equal(HttpStatusCode.OK, freshStatus);
        JsonWebToken minted = await ValidateMintedAsync(freshBody.GetProperty("access_token").GetString()!, "DocumentService");
        Assert.Equal(2, minted.GetPayloadValue<int>("auth_version"));
    }

    // --- helpers ---

    private async Task<(HttpStatusCode Status, JsonElement Body)> ExchangeAsync(
        string subject, string actor, string? audience, string scope)
    {
        var fields = new List<KeyValuePair<string, string>>
        {
            new("grant_type", TokenConstants.GrantType),
            new("subject_token", subject),
            new("subject_token_type", TokenConstants.JwtTokenType),
            new("actor_token", actor),
            new("actor_token_type", TokenConstants.JwtTokenType),
            new("scope", scope),
        };
        if (audience is not null)
            fields.Add(new("audience", audience));

        HttpResponseMessage response = await _client.PostAsync("/oauth2/token", new FormUrlEncodedContent(fields));
        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);
        return (response.StatusCode, doc.RootElement.Clone());
    }

    private async Task<JsonWebToken> ValidateMintedAsync(string token, string audience)
    {
        var handler = new JsonWebTokenHandler();
        TokenValidationResult result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = TokenConstants.Issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _keys.SecurityKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
        });

        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }
}
