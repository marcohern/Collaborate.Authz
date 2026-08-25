namespace Collaborate.Authz.Responses
{
    public class TokenResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public string Scope { get; set; } = string.Empty;
    }
}
