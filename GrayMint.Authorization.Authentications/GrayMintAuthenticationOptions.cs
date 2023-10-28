namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthenticationOptions
{
    [Obsolete ("Use Issuer")]
    public string BotIssuer { get => Issuer; init { Issuer = value; Console.WriteLine("You are using an obsoleted property."); } }

    [Obsolete ("Use Audience")]
    public string? BotAudience { get => Audience; init { Audience = value; Console.WriteLine("You are using an obsoleted property."); } }

    [Obsolete ("Use Secret")]
    public byte[] BotKey { get => Secret; init { Secret = value; Console.WriteLine("You are using an obsoleted property."); } } 

    public required byte[] Secret { get; init; }
    public required string Issuer { get; init; }
    public string? Audience { get; init; }
    public TimeSpan CacheTimeout { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan OpenIdConfigTimeout { get; init; } = TimeSpan.FromMinutes(30);
    public TimeSpan IdTokenExpiration { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan AccessTokenShortExpiration { get; init; } = TimeSpan.FromDays(3);
    public TimeSpan AccessTokenLongExpiration { get; init; } = TimeSpan.FromDays(30);
    public string? GoogleClientId { get; init; }
    public string? CognitoClientId { get; init; }
    public string? CognitoArn { get; init; }

    public void Validate(bool isProduction)
    {
        if (string.IsNullOrEmpty(Issuer))
            throw new Exception($"{nameof(Issuer)} has not been set in {nameof(GrayMintAuthenticationOptions)}.");

        if (Secret == null! || Secret.Length == 0)
            throw new Exception($"{nameof(Secret)} has not been set in {nameof(GrayMintAuthenticationOptions)}.");

        if (isProduction && Secret.All(x => x == 0))
            throw new Exception($"{nameof(Secret)} value is not valid for Production..");
    }
}