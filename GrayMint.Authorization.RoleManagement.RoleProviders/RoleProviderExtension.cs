using System;
using System.Threading.Tasks;
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
        services.AddDbContext<RoleDbContext>(dbOptionsAction);
        services.AddSingleton(Options.Create(options));
        services.AddScoped<IRoleProvider, RoleProvider>();
        services.AddScoped<IRoleAuthorizationProvider, RoleProvider>();
        services.AddScoped<IRoleResourceProvider, RoleResourceProvider>();
    }

    public static async Task UseGrayMintRoleProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<RoleDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, RoleDbContext.Schema, nameof(RoleDbContext.UserRoles));
    }
}