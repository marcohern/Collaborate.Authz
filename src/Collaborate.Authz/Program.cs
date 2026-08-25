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

app.MapControllers();

// RFC 8693 token-exchange endpoint (the on-behalf-of slice) lives in Oauth2Controller.

// Public keys so a real downstream could validate minted tokens offline. Closes the loop for the demo.
app.MapGet("/.well-known/jwks.json", (SigningKeyProvider keys) =>
    Results.Json(new { keys = new[] { keys.PublicJwkJson() } }));

app.Run();

// Exposed so the test project's WebApplicationFactory<Program> can boot the real pipeline.
public partial class Program;
