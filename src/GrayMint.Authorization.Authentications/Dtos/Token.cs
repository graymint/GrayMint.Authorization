using System.Security.Claims;
using System.Text.Json.Serialization;

namespace GrayMint.Authorization.Authentications.Dtos;

/// <summary>
/// A signed token.
/// </summary>
public class Token
{
    /// <summary>
    /// The token itself.
    /// </summary>
    public required string Value { get; init; }
    /// <summary>
    /// When it stops working, in UTC.
    /// </summary>
    public required DateTime ExpirationTime { get; init; }
    /// <summary>
    /// The scheme it goes with in the Authorization header, such as `Bearer`.
    /// </summary>
    public required string Scheme { get; init; }
    /// <summary>
    /// When it was made, in UTC.
    /// </summary>
    public required DateTime IssuedTime { get; init; }

    [JsonIgnore] public ClaimsPrincipal? ClaimsPrincipal { get; init; }
}