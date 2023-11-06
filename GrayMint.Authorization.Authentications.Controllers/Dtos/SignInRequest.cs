namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

public class SignInRequest
{
    public required string IdToken { get; init; }
    public bool LongExpiration { get; init; }
    public bool WithRefreshToken { get; init; }
}