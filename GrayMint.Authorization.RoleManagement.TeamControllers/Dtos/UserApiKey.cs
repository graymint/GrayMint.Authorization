namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserApiKey
{
    public required string AccessToken { get; init; }
    public required string Scheme { get; init; }
    public required DateTime ExpirationTime { get; init; }
    public required DateTime IssuedTime { get; init; }
    public required Guid UserId { get; init; }
}