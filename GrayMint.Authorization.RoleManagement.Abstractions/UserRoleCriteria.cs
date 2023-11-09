namespace GrayMint.Authorization.RoleManagement.Abstractions;

public class UserRoleCriteria
{
    public string? ResourceId { get; set; }
    public string? RoleId { get; set; }
    public string? UserId { get; set; }
}