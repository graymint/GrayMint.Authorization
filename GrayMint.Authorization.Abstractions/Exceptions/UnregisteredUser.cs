using System;

namespace GrayMint.Authorization.Abstractions.Exceptions;

public class UnregisteredUser : Exception
{
    public UnregisteredUser() : base("User has not been registered.")
    {
    }
}