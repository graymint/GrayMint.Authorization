using System;
using System.Threading.Tasks;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public static class SimpleRoleProviderExtension
{
    public static void AddGrayMintSimpleRoleProvider(
        this IServiceCollection services,
        SimpleRoleProviderOptions? options,
        Action<DbContextOptionsBuilder>? dbOptionsAction = null)
    {
        options ??= new SimpleRoleProviderOptions();
        services.AddDbContext<SimpleRoleDbContext>(dbOptionsAction);
        services.AddSingleton(Options.Create(options));
        services.AddScoped<IRoleProvider, SimpleRoleProvider>();
        services.AddScoped<IRoleAuthorizationProvider, SimpleRoleProvider>();
        services.AddScoped<IResourceProvider, ResourceProvider>();
    }

    public static async Task UseGrayMintSimpleRoleProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SimpleRoleDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, SimpleRoleDbContext.Schema, nameof(SimpleRoleDbContext.UserRoles));
    }
}