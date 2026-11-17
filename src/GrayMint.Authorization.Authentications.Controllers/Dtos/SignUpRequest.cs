using GrayMint.Authorization.Authentications.Dtos;

namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

/// <summary>
/// A sign-up with an ID token.
/// </summary>
public class SignUpRequest
{
    /// <summary>
    /// The ID token from one of the service's identity providers.
    /// </summary>
    public required string IdToken { get; init; }
    /// <summary>
    /// Which refresh token to get, if any; none if left out.
    /// </summary>
    public RefreshTokenType RefreshTokenType { get; init; } = RefreshTokenType.None;
}