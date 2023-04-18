namespace GrayMint.Authorization.RoleManagement.TeamControllers.Exceptions;

public class UnregisteredUser : Exception
{
    public UnregisteredUser() : base("User has not been registered.")
    {
    }
}