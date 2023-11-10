namespace GrayMint.Authorization.UserManagement.UserProviders;

public class UserProviderOptions
{
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(30);
}