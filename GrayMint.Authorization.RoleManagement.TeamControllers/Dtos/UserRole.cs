using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserRole : Abstractions.UserRole
{
    public required User? User { get; init; }
}