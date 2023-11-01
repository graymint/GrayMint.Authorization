namespace GrayMint.Authorization.Authentications;

public class AccessToken
{
    public required string Value { get; init; }
    public required DateTime Expires { get; init; }
    public required string Scheme { get; init; }
}