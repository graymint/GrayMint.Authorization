using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamRole : IRole
{
    private readonly IRole _role;

    public TeamRole(IRole role)
    {
        _role = role;
    }

    public Guid RoleId => _role.RoleId;

    public string RoleName => _role.RoleName;

    public string? Description => _role.Description;
}