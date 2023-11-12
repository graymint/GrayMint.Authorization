using System.Security.Claims;

namespace GrayMint.Authorization.Authentications.Dtos;

public class ApiKeyOptions
{
    public TokenOptions TokenOptions { get; init; } = new();
    public ClaimsIdentity ClaimsIdentity { get; init; } = new();
    public RefreshTokenType RefreshTokenType { get; init; }
    public DateTime? AccessTokenExpirationTime { get; init; }
    public DateTime? RefreshTokenExpirationTime { get; init; }
    public DateTime? RefreshTokenMaxExpirationTime { get; init; }
}