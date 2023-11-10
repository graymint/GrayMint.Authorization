using System.Linq;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Abstractions;

public static class UserAuthorizationCacheExtension
{
    public static IServiceCollection AddGrayMintUserAuthorizationCache(this IServiceCollection services)
    {
        if (services.All(x => x.ServiceType != typeof(UserAuthorizationCache)))
            services.AddSingleton<UserAuthorizationCache>();
        return services;
    }
}