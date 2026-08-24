namespace Collaborate.Authz.Security
{
    public class GrantedScopes
    {

        public static IReadOnlyList<string> Compute(
            IReadOnlyCollection<string> requested,
            IReadOnlySet<string> subject,
            IReadOnlySet<string> actor,
            IReadOnlySet<string> downstream)
            {
                IEnumerable<string> basis = requested.Count == 0 ? subject : requested;
                return basis
                    .Where(s => subject.Contains(s) && actor.Contains(s) && downstream.Contains(s))
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
            }
    }
}
