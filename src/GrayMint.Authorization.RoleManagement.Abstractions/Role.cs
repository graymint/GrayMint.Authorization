namespace GrayMint.Authorization.RoleManagement.Abstractions;

/// <summary>
/// A role a team member can have on a resource.
/// </summary>
public class Role
{
    /// <summary>
    /// The role's id.
    /// </summary>
    public required string RoleId { get; init; }
    /// <summary>
    /// The role's name.
    /// </summary>
    public required string RoleName { get; init; }
    /// <summary>
    /// What the role is for.
    /// </summary>
    public string? Description { get; init; }
}