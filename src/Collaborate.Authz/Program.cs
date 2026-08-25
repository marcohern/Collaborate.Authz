using Collaborate.Authz.BusinessLogic;
using Collaborate.Authz.Middleware;
using Collaborate.Authz.Security;
using Collaborate.Authz.TokenExchange;
using Collaborate.Authz.Utilities;
using Microsoft.IdentityModel.JsonWebTokens;

var builder = WebApplication.CreateBuilder(args);

// Singletons: the signing key must be stable for the process, and the stubs are stateless/shared.
builder.Services.AddSingleton<SigningKeyProvider>();
builder.Services.AddSingleton<InboundTokenValidator>();
builder.Services.AddSingleton<IPermissionStore, InMemoryPermissionStore>();
builder.Services.AddSingleton<IActorTrustPolicy, ActorTrustPolicy>();
builder.Services.AddSingleton<IDownstreamRegistry, DownstreamRegistry>();
builder.Services.AddSingleton<ITokenMinter, JwtTokenMinter>();
builder.Services.AddSingleton<TokenExchangeHandler>();
builder.Services.AddSingleton<MintRequestValidator>();
builder.Services.AddSingleton<JsonWebTokenHandler>();
builder.Services.AddSingleton<TokenDescriptorCreator>();

// Attribute-routed controllers (Oauth2Controller).
builder.Services.AddControllers();

var app = builder.Build();

// Outermost middleware: any exception that escapes an endpoint is rendered as RFC 6749 JSON,
// never an HTML developer page or an empty 500 body.
app.UseJsonErrorHandling();

// Routing must run explicitly here rather than being implied by MapControllers: the bearer middleware reads
// the matched endpoint's metadata, and before routing there is no matched endpoint to read.
app.UseRouting();

// Validates Authorization: Bearer tokens, but only for endpoints marked [RequireBearerToken] — the login and
// token-exchange endpoints below are anonymous by design.
app.UseBearerTokenValidation();

app.MapControllers();

// RFC 8693 token-exchange endpoint (the on-behalf-of slice) lives in Oauth2Controller.

// Public keys so a real downstream could validate minted tokens offline. Closes the loop for the demo.
app.MapGet("/.well-known/jwks.json", (SigningKeyProvider keys) =>
    Results.Json(new { keys = new[] { keys.PublicJwkJson() } }));

// A protected resource: the smallest thing that proves a token minted by /api/Oauth2/token can be presented
// back and consumed. Reaching the body at all means the bearer middleware validated the token and built the
// principal below.
app.MapGet("/api/me", (HttpContext ctx) => Results.Json(new
{
    sub = ctx.User.FindFirst("sub")?.Value,
    username = ctx.User.FindFirst("username")?.Value,
    name = ctx.User.FindFirst("name")?.Value,
}))
.WithMetadata(new RequireBearerTokenAttribute());

app.Run();

// Exposed so the test project's WebApplicationFactory<Program> can boot the real pipeline.
public partial class Program;
