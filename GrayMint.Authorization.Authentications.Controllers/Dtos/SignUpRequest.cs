using GrayMint.Authorization.Authentications.Dtos;

namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

public class SignUpRequest
{
    public required string IdToken { get; init; }
    public RefreshTokenType RefreshTokenType { get; init; }
}