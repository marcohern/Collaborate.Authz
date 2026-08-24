using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Authz.Utilities
{
    public class Claim
    {
        public static string? String(TokenValidationResult result, string type) =>
        result.Claims.TryGetValue(type, out var value) ? value?.ToString() : null;

        public static int? Int(TokenValidationResult result, string type) =>
            result.Claims.TryGetValue(type, out var value) && value is not null && int.TryParse(value.ToString(), out int parsed)
                ? parsed
                : null;
    }
}
