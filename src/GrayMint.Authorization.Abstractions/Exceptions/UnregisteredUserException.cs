using System.Net;

namespace GrayMint.Authorization.Abstractions.Exceptions;

public sealed class UnregisteredUserException : Exception
{
    public UnregisteredUserException() : base("User has not been registered.")
    {
        Data["HttpStatusCode"] = (int)HttpStatusCode.Forbidden;
    }
}