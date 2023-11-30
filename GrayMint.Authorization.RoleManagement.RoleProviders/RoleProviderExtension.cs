using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.RoleProviders;

public static class RoleProviderExtension
{
    public static void AddGrayMintRoleProvider(
        this IServiceCollection services,
        RoleProviderOptions options,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        services.AddSingleton<UserAuthorizationCache>();
        services.AddSingleton(Options.Create(options));
        services.AddScoped<IRoleProvider, RoleProvider>();
        services.AddScoped<IRoleAuthorizationProvider, RoleProvider>();
        services.AddScoped<IRoleResourceProvider, RoleResourceProvider>();
        services.AddDbContext<RoleDbContext>(dbOptionsAction);
    }

    public static async Task UseGrayMintRoleProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<RoleDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, RoleDbContext.Schema, nameof(RoleDbContext.UserRoles));
    }
}