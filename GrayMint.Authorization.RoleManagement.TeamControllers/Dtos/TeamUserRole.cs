using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamUserRole : IUserRole
{
    private readonly IUserRole _userRole;
    
    public TeamUserRole(IUserRole userRole, IUser? user)
    {
        _userRole = userRole;
        User = user != null ? new TeamUser(user) : null;
        Role = new TeamRole(userRole.Role);
    }


    public TeamUser? User { get; }
    public string ResourceId => _userRole.ResourceId;
    public Guid UserId => _userRole.UserId;
    public TeamRole Role { get; } // returning an interface will cause problem for nswag client generator
    IRole IUserRole.Role => _userRole.Role;

}