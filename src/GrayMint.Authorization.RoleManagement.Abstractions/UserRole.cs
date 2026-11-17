namespace GrayMint.Authorization.RoleManagement.Abstractions;

/// <summary>
/// A user's role on a resource.
/// </summary>
public class UserRole
{
    /// <summary>
    /// The resource's id.
    /// </summary>
    public required string ResourceId { get; init; }
    /// <summary>
    /// The user's id.
    /// </summary>
    public required string UserId { get; init; }
    /// <summary>
    /// The role.
    /// </summary>
    public required Role Role { get; init; }

    /// <summary>
    /// When the member first made a request to the resource, in UTC; until then the team sees only their email.
    /// </summary>
    public required DateTime? ConfirmedTime { get; init; }
}