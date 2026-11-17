using System.Text.Json.Serialization;

namespace GrayMint.Authorization.Authentications.Dtos;

/// <summary>
/// Which refresh token a sign-in gets, if any.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RefreshTokenType
{
    /// <summary>
    /// No refresh token: the user signs in again once the access token expires.
    /// </summary>
    None,
    /// <summary>
    /// A shorter-lived one, for a browser.
    /// </summary>
    Web,
    /// <summary>
    /// A longer-lived one, for an app the user installed.
    /// </summary>
    App
}