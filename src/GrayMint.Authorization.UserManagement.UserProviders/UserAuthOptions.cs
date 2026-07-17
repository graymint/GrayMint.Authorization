using GrayMint.Authorization.Abstractions;

namespace GrayMint.Authorization.UserManagement.UserProviders;

public class UserProviderOptions
{
    public TimeSpan CacheTimeout { get; set; } = AuthorizationConstants.CacheTimeout;
}