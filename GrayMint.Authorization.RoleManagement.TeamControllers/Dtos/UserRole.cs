using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserRole : IUserRole
{
    private readonly IUserRole _userRole;

    public UserRole(IUserRole userRole, IUser? user)
    {
        _userRole = userRole;
        ResourceId = _userRole.ResourceId;
        User = user != null ? new User(user) : null;
        Role = new Role(userRole.Role);
    }

    public User? User { get; set; }
    public string ResourceId { get; internal set; }
    public Guid UserId => _userRole.UserId;
    IRole IUserRole.Role => _userRole.Role;
    public Role Role { get; }
}