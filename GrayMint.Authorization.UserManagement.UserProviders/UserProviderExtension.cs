using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.UserProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.UserManagement.UserProviders;

public static class UserProviderExtension
{
    public static IServiceCollection AddGrayMintUserProvider(this IServiceCollection services,
        UserProviderOptions? userOptions)
    {
        userOptions ??= new UserProviderOptions();
        services.AddSingleton<UserAuthorizationCache>();
        services.AddSingleton(Options.Create(userOptions));
        services.AddScoped<IUserProvider, UserProvider>();
        services.AddScoped<IAuthorizationProvider, AuthorizationProvider>();
        return services;
    }

    public static IServiceCollection AddGrayMintUserProviderDb(
        this IServiceCollection services,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        services.AddDbContext<UserDbContext>(dbOptionsAction);
        return services;
    }

    public static async Task<IServiceProvider> UseGrayMintUserProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<UserDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database);
        return serviceProvider;
    }
}