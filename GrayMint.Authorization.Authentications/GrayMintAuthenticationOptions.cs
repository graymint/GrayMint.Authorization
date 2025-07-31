using GrayMint.Authorization.Authentications.Dtos;

namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthenticationOptions
{
    [Obsolete ("Use Issuer")]
    public string BotIssuer { get => Issuer; init { Issuer = value; Console.WriteLine("You are using an obsoleted property. Property: BotIssuer"); } }

    [Obsolete ("Use Audience")]
    public string? BotAudience { get => Audience; init { Audience = value; Console.WriteLine("You are using an obsoleted property. Property: BotAudience"); } }

    [Obsolete ("Use Secret")]
    public byte[] BotKey { get => Secret; init { Secret = value; Console.WriteLine("You are using an obsoleted property. Property: BotKey"); } } 

    public required byte[] Secret { get; init; }
    public IEnumerable<byte[]> Secrets { get; init; } = [];
    public required string Issuer { get; init; }
    public string? Audience { get; init; }
    public TimeSpan CacheTimeout { get; init; } = TimeSpan.FromMinutes(10);
    public TimeSpan OpenIdConfigTimeout { get; init; } = TimeSpan.FromMinutes(30);
    public TimeSpan IdTokenTimeout { get; init; } = TimeSpan.FromMinutes(15);
    public TimeSpan AccessTokenTimeout { get; init; } = TimeSpan.FromMinutes(20);
    public TimeSpan RefreshTokenWebTimeout { get; init; } = TimeSpan.FromDays(2);
    public TimeSpan RefreshTokenAppTimeout { get; init; } = TimeSpan.FromDays(30);
    public TimeSpan SessionWebTimeout { get; init; } = TimeSpan.FromDays(30);
    public TimeSpan SessionAppTimeout { get; init; } = TimeSpan.FromDays(360);
    public bool AllowUserSelfRegister { get; init; }
    public bool AllowUserApiKey { get; init; }
    public Uri? SignInRedirectUrl { get; init; }
    public bool AllowRefreshToken { get; init; }
    public OpenIdProvider[] OpenIdProviders { get; init; } = [];

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