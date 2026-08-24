namespace Collaborate.Authz.Utilities
{
    public class JsonResults
    {
        public static IResult Error(string error, string description, int statusCode)
        {
            var result = new
            {
                error,
                error_description = description
            };
            return Results.Json(result, statusCode: statusCode);
        }
    }
}
