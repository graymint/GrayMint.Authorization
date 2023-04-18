namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserApiKey
{
    public required Guid UserId { get; set; }
    public required string Authorization { get; init; }
}