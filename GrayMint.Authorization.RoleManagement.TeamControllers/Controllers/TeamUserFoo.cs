namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

public class TeamUser<TUser, TRole>
{
    public required TUser User { get; init; }
    public required TRole[] Roles { get; init; }
}