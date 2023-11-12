namespace GrayMint.Authorization.Authentications.Dtos;

public class ValidateOptions
{
    public bool ValidateAuthCode { get; init; } 
    public bool ValidateSubject { get; init; }
}