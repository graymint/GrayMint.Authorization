namespace GrayMint.Authorization.Authentications.Dtos;

public class TokenOptions
{
    public string? Subject { get; init; }
    public string? Email { get; init; }
    public string? AuthCode { get; init; }
    public DateTime? AuthTime { get; init; }
    public bool ValidateAuthCode { get; init; } = true;
    public bool ValidateSubject { get; init; } = true;
}