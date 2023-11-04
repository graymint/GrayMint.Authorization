namespace GrayMint.Authorization.Authentications;

public class ApiKey
{
    public required Token AccessToken { get; init; }
    public required Token? RefreshToken { get; init; }
    public required string UserId { get; init; }
}