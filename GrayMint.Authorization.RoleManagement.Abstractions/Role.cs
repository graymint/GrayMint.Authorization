
namespace GrayMint.Authorization.RoleManagement.Abstractions;

public class Role
{
    public required string RoleId { get; init; }
    public required string RoleName { get; init; }
    public string? Description { get; init; }
}
