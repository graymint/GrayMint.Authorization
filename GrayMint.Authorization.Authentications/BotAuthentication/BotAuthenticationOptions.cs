namespace GrayMint.Authorization.Authentications.BotAuthentication;

public class BotAuthenticationOptions
{
    public required string BotIssuer { get; set; }
    public string? BotAudience { get; set; }
    public required byte[] BotKey { get; set; }
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(10);

    public void Validate(bool isProduction)
    {
        if (string.IsNullOrEmpty(BotIssuer))
            throw new Exception($"{nameof(BotIssuer)} has not been set in {nameof(BotAuthenticationOptions)}.");

        if (BotKey == null! || BotKey.Length == 0)
            throw new Exception($"{nameof(BotKey)} has not been set in {nameof(BotAuthenticationOptions)}.");

        if (isProduction && BotKey.All(x => x == 0))
            throw new Exception($"{nameof(BotKey)} value is not valid for Production..");
    }
}