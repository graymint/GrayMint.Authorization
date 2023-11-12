namespace GrayMint.Authorization.Authentications.Dtos;

public class TokenOptions
{
    public bool ValidateAuthCode { get; init; } = true;
    public bool ValidateSubject { get; init; } = true;
}