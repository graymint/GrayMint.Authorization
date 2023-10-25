using System.Security.Claims;

namespace GrayMint.Authorization.Authentications.BotAuthentication;

public class CreateTokenParams
{
    public string? Subject { get; init; }
    public string? Email { get; init; }
    public string? AuthCode { get; init; }
    public DateTime? AuthTime { get; init; }
    public DateTime ExpirationTime { get; init; } = DateTime.Now.AddYears(14);
    public ClaimsIdentity? ClaimsIdentity { get; init; }
    public string TokenUse { get; set; } = "access";
}