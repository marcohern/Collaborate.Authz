using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Security;

/// <summary>
/// Provides the RSA signing key for minted tokens and publishes the matching public JWK.
///
/// DEV ONLY: the key is generated in-process and lives for the lifetime of the app. In production this
/// is backed by AWS KMS / a managed key store with rotation (see DESIGN.md) — we never hand-roll key
/// management. Because the same instance both signs outbound tokens and validates inbound test tokens,
/// the demo is a closed, verifiable loop without a real IdP.
/// </summary>
public sealed class SigningKeyProvider : IDisposable
{
    private readonly RSA _rsa;

    public string KeyId { get; } = "dev-key-1";

    /// <summary>
    /// DEV ONLY: if a <c>dev-signing-key.pem</c> sits next to the app (or is pointed at by
    /// <c>AUTHZ_DEV_SIGNING_KEY_PEM</c>), use it so the key is stable across restarts and an out-of-process
    /// script can mint stand-in subject/actor tokens for manual testing. Otherwise generate an ephemeral key.
    /// </summary>
    public SigningKeyProvider()
    {
        _rsa = RSA.Create(2048);

        string path = Environment.GetEnvironmentVariable("AUTHZ_DEV_SIGNING_KEY_PEM")
            ?? Path.Combine(AppContext.BaseDirectory, "dev-signing-key.pem");

        if (File.Exists(path))
            _rsa.ImportFromPem(File.ReadAllText(path));
    }

    // Signature providers are not cached: with a fixed dev key every instance of this class would otherwise
    // share one cache entry, and a disposed instance's RSA would be handed to the next one.
    public RsaSecurityKey SecurityKey => new(_rsa)
    {
        KeyId = KeyId,
        CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false },
    };

    public SigningCredentials SigningCredentials => new(SecurityKey, SecurityAlgorithms.RsaSha256);

    /// <summary>Public-key-only JWK projection suitable for a /.well-known/jwks.json document.</summary>
    public object PublicJwkJson()
    {
        RSAParameters p = _rsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid = KeyId,
            n = Base64UrlEncoder.Encode(p.Modulus),
            e = Base64UrlEncoder.Encode(p.Exponent),
        };
    }

    public void Dispose() => _rsa.Dispose();
}
