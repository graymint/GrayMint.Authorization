namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

public class RefreshTokenRequest
{
    public required string RefreshToken { get; init; }
}