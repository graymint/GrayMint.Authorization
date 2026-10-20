namespace GrayMint.Authorization.RoleManagement.Abstractions;

public class UserRole
{
    public required string ResourceId { get; init; }
    public required string UserId { get; init; }
    public required Role Role { get; init; }

    // the member's first request to the resource; until then the team sees only their email
    public required DateTime? ConfirmedTime { get; init; }
}