using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public static class ResourceProviderExtension
{
    public static void AddGrayMintResourceProvider(
        this IServiceCollection services,
        ResourceProviderOptions options,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        services.AddDbContext<ResourceDbContext>(dbOptionsAction);
        services.AddSingleton(Options.Create(options));
        services.AddScoped<IRoleResourceProvider, RoleResourceProvider>();
        services.AddScoped<IResourceProvider, ResourceProvider>();
    }

    public static async Task UseGrayMintResourceProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ResourceDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database, ResourceDbContext.Schema, nameof(ResourceDbContext.Resources));
    }
}