namespace GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

/// <summary>
/// A team member, with their roles on a resource.
/// </summary>
public class TeamUser<TUser, TRole>
{
    /// <summary>
    /// The member.
    /// </summary>
    public required TUser User { get; init; }
    /// <summary>
    /// Their roles on the resource.
    /// </summary>
    public required IReadOnlyList<TRole> Roles { get; init; }
}