using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamUser
{
    public required User User { get; init; }
    public required IReadOnlyList<Role> Roles { get; init; }
}