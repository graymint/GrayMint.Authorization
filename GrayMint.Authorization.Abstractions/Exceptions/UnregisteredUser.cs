using System;
using System.Net;

namespace GrayMint.Authorization.Abstractions.Exceptions;

public sealed class UnregisteredUser : Exception
{
    public UnregisteredUser() : base("User has not been registered.")
    {
        Data["HttpStatusCode"] = (int)HttpStatusCode.Forbidden;
    }
}