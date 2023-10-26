namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthenticationOptions
{
    [Obsolete ("Use Issuer")]
    public string BotIssuer { get => Issuer; init { Issuer = value; Console.WriteLine("You are using an obsoleted property."); } }

    [Obsolete ("Use Audience")]
    public string? BotAudience { get => Audience; init { Audience = value; Console.WriteLine("You are using an obsoleted property."); } }

    [Obsolete ("Use Secret")]
    public byte[] BotKey { get => Secret; init { Secret = value; Console.WriteLine("You are using an obsoleted property."); } } 

    public required byte[] Secret { get; set; }
    public required string Issuer { get; set; }
    public string? Audience { get; set; }
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(10);
    public TimeSpan IdTokenExpiration { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan AccessTokenShortExpiration { get; set; } = TimeSpan.FromDays(3);
    public TimeSpan AccessTokenLongExpiration { get; set; } = TimeSpan.FromDays(30);
    public string? GoogleClientId { get; set; }

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