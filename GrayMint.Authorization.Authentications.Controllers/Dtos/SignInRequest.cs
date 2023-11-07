using GrayMint.Authorization.Authentications.Dtos;

namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

public class SignInRequest
{
    public required string IdToken { get; init; }
    public RefreshTokenType RefreshTokenType { get; init; }
}