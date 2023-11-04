namespace GrayMint.Authorization.RoleManagement.Abstractions;

public class UserRole
{
    public required string ResourceId { get; init; }
    public required string UserId { get; init; }
    public required Role Role { get; init; }
}