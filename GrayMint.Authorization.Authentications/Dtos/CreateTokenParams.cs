using System.Security.Claims;

namespace GrayMint.Authorization.Authentications.Dtos;

public class CreateTokenParams
{
    public string? Subject { get; set; }
    public string? Email { get; set; }
    public string? AuthCode { get; set; }
    public DateTime? AuthTime { get; init; }
    public ClaimsIdentity? ClaimsIdentity { get; set; }
}