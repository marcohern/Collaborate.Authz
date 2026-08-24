#:package Microsoft.IdentityModel.JsonWebTokens@8.*

// DEV ONLY: mints a stand-in subject_token / actor_token for manual testing of POST /oauth2/token.
// Stands in for the central IdP: same issuer, same dev signing key the service validates against.
//
//   dotnet run tools/mint-token.cs -- <sub> [authVersion] [lifetimeSeconds] [pemPath]
//
// Requires .NET 10 (file-based app). The default pem is dev-signing-key.pem at the repo root.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

if (args.Length == 0)
{
    Console.Error.WriteLine("usage: dotnet run tools/mint-token.cs -- <sub> [authVersion] [lifetimeSeconds] [pemPath]");
    return 1;
}

string subject = args[0];
int authVersion = args.Length > 1 ? int.Parse(args[1]) : 1;
int lifetimeSeconds = args.Length > 2 ? int.Parse(args[2]) : 3600;
// A file-based app builds into a temp dir, so locate the key by walking up from the working directory.
string? pemPath = args.Length > 3 ? args[3] : FindKeyUpwards(Directory.GetCurrentDirectory());

if (pemPath is null || !File.Exists(pemPath))
{
    Console.Error.WriteLine("dev-signing-key.pem not found; run from the repo or pass its path as the 4th argument.");
    return 1;
}

static string? FindKeyUpwards(string start)
{
    for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
    {
        string candidate = Path.Combine(dir.FullName, "dev-signing-key.pem");
        if (File.Exists(candidate))
            return candidate;
    }
    return null;
}

using var rsa = RSA.Create();
rsa.ImportFromPem(File.ReadAllText(pemPath));

DateTime now = DateTime.UtcNow;
Console.WriteLine(new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
{
    // Must match TokenConstants.Issuer — the validator checks it.
    Issuer = "https://authz.collaborate.local",
    IssuedAt = now,
    NotBefore = now,
    Expires = now.AddSeconds(lifetimeSeconds),
    SigningCredentials = new SigningCredentials(
        new RsaSecurityKey(rsa) { KeyId = "dev-key-1" },
        SecurityAlgorithms.RsaSha256),
    Claims = new Dictionary<string, object>
    {
        ["sub"] = subject,
        ["auth_version"] = authVersion,
    },
}));

return 0;
