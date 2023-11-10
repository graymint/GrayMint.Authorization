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
    public static void AddGrayMintUserProvider(this IServiceCollection services,
        UserProviderOptions? userOptions,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        userOptions ??= new UserProviderOptions();
        services.AddSingleton<UserAuthorizationCache>();
        services.AddSingleton(Options.Create(userOptions));
        services.AddScoped<IUserProvider, UserProvider>();
        services.AddScoped<IAuthorizationProvider, AuthorizationProvider>();
        services.AddDbContext<UserDbContext>(dbOptionsAction);
    }

    public static async Task UseGrayMintUserProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<UserDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, UserDbContext.Schema, nameof(UserDbContext.Users));
    }
}