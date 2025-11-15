using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public static class ResourceProviderExtension
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddGrayMintResourceProvider(ResourceProviderOptions options,
            Action<DbContextOptionsBuilder>? dbOptionsAction)
        {
            services.AddSingleton<UserAuthorizationCache>();
            services.AddSingleton(Options.Create(options));
            services.AddScoped<IRoleResourceProvider, RoleResourceProvider>();
            services.AddScoped<IResourceProvider, ResourceProvider>();
            if (dbOptionsAction != null)
                services.AddGrayMintResourceProviderDb(dbOptionsAction);

            return services;
        }

        public IServiceCollection AddGrayMintResourceProviderDb(Action<DbContextOptionsBuilder> dbOptionsAction)
        {
            services.AddDbContext<ResourceDbContext>(dbOptionsAction);
            return services;
        }
    }

    public static async Task<IServiceProvider> UseGrayMintResourceProvider(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<ResourceDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database);
        return serviceProvider;
    }
}