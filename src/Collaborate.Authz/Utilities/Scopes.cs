namespace Collaborate.Authz.Utilities
{
    public class Scopes
    {
        public static IReadOnlyCollection<string> Parse(string raw) =>
        raw.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
