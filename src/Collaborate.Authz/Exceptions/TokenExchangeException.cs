namespace Collaborate.Authz.Exceptions
{
    public class TokenExchangeException : AuthzException
    {
        public string ErrorType { get; private set; }
        public int StatusCode { get; private set; }
        public TokenExchangeException(string type, string message, int statusCode) : base(message)
        { 
            ErrorType = type;
            StatusCode = statusCode;
        }
        public TokenExchangeException(string type, string message, int statusCode, Exception innerException) : base(message, innerException)
        { 
            ErrorType = type;
            StatusCode = statusCode;
        }
    }
}
