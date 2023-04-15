using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders;

public static class SimpleUserProviderExtension
{
    public static void AddGrayMintSimpleUserProvider(this IServiceCollection services,
        SimpleUserProviderOptions? userOptions,
        Action<DbContextOptionsBuilder>? dbOptionsAction = null)
    {
        userOptions ??= new SimpleUserProviderOptions();
        services.AddDbContext<SimpleUserDbContext>(dbOptionsAction);
        services.AddSingleton(Options.Create(userOptions));
        services.AddScoped<IUserProvider, SimpleUserProvider>();
        services.AddScoped<IAuthorizationProvider, SimpleAuthenticationProvider>();
    }

    public static async Task UseGrayMintSimpleUserProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SimpleUserDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, SimpleUserDbContext.Schema, nameof(SimpleUserDbContext.Users));
    }
}