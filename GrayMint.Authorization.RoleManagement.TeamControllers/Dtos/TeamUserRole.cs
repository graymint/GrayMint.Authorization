using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamUserRole : UserRole
{
    public required User? User { get; init; }
}