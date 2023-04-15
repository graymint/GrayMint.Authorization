namespace GrayMint.Authorization.RoleManagement.RoleControllers.Exceptions;

public class UnregisteredUser : Exception
{
    public UnregisteredUser() : base("User has not been registered.")
    {
    }
}