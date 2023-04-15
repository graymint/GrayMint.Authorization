namespace GrayMint.Authorization.RoleManagement.RoleControllers.Dtos;

public class TeamAddUserParam
{
    public required string Email { get; set; }
    public required Guid RoleId { get; set; }
}