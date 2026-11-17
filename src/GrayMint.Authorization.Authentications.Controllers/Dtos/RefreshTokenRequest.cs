namespace GrayMint.Authorization.Authentications.Controllers.Dtos;

/// <summary>
/// A request for a new access token.
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// The refresh token.
    /// </summary>
    public required string RefreshToken { get; init; }
}