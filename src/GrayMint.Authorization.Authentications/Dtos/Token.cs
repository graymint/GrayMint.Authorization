using System.Security.Claims;
using System.Text.Json.Serialization;

namespace GrayMint.Authorization.Authentications.Dtos;

public class Token
{
    public required string Value { get; init; }
    public required DateTime ExpirationTime { get; init; }
    public required string Scheme { get; init; }
    public required DateTime IssuedTime { get; init; }

    [JsonIgnore] public ClaimsPrincipal? ClaimsPrincipal { get; init; }
}