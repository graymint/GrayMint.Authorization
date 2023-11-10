using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.NestedResourceProviders;

public static class NestedResourceProviderExtension
{
    public static void AddGrayMintNestedResourceProvider(
        this IServiceCollection services,
        NestedResourceProviderOptions options,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        services.AddDbContext<ResourceDbContext>(dbOptionsAction);
        services.AddSingleton(Options.Create(options));
        services.AddScoped<IRoleResourceProvider, NestedRoleResourceProvider>();
        services.AddScoped<INestedResourceProvider, NestedResourceProvider>();
    }

    public static async Task UseGrayMintNestedResourceProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ResourceDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, ResourceDbContext.Schema, nameof(ResourceDbContext.Resources));
    }
}