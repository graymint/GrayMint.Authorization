using System.Text.Json.Serialization;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserApiKey
{
    [JsonPropertyName("expiration")]
    public required DateTime ExpirationTime { get; init; }
    public required Guid UserId { get; init; }
    public required string Authorization { get; init; }
}