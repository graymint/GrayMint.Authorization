namespace GrayMint.Authorization.UserManagement.SimpleUserProviders;

public class SimpleUserProviderOptions
{
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(10);
}