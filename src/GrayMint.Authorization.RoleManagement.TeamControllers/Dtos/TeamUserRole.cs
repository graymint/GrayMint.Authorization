using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

/// <summary>
/// A team member's role on a resource, with the member.
/// </summary>
public class TeamUserRole : UserRole
{
    /// <summary>
    /// The member; only their email until their first request to the resource.
    /// </summary>
    public required User? User { get; init; }
}