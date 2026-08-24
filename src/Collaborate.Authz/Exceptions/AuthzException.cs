namespace Collaborate.Authz.Exceptions
{
    public class AuthzException : ApplicationException
    {
        public AuthzException() : base() { }
        public AuthzException(string message) : base(message) { }
        public AuthzException(string message, Exception innerException) : base(message, innerException) { }
    }
}
