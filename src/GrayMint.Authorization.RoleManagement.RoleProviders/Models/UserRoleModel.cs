namespace GrayMint.Authorization.RoleManagement.RoleProviders.Models;

internal class UserRoleModel
{
    public int UserRoleId { get; init; }
    public required string ResourceId { get; set; }
    public required Guid UserId { get; set; }
    public required Guid RoleId { get; set; }
}