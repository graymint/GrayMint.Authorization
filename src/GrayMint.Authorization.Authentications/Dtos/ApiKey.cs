namespace GrayMint.Authorization.Authentications.Dtos;

/// <summary>
/// An API key: the access token to call the API with, and the refresh token that gets a new one.
/// </summary>
public class ApiKey
{
    /// <summary>
    /// The token to send as `Authorization: Bearer &lt;token&gt;`.
    /// </summary>
    public required Token AccessToken { get; init; }
    /// <summary>
    /// The token that gets a new access token when this one expires; none unless the sign-in asked for one.
    /// </summary>
    public required Token? RefreshToken { get; init; }
    /// <summary>
    /// The id of the user the key belongs to.
    /// </summary>
    public required string UserId { get; init; }
}