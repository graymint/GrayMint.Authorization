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
    extension(IServiceCollection services)
    {
        public IServiceCollection AddGrayMintRoleProvider(RoleProviderOptions options)
        {
            services.AddSingleton<UserAuthorizationCache>();
            services.AddSingleton(Options.Create(options));
            services.AddScoped<IRoleProvider, RoleProvider>();
            services.AddScoped<IRoleAuthorizationProvider, RoleProvider>();
            services.AddScoped<IRoleResourceProvider, RoleResourceProvider>();
            return services;
        }

        public IServiceCollection AddGrayMintRoleProviderDb(Action<DbContextOptionsBuilder> dbOptionsAction)
        {
            services.AddDbContext<RoleDbContext>(dbOptionsAction);
            return services;
        }
    }

    public static async Task<IServiceProvider> UseGrayMintRoleProvider(
        this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<RoleDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database);
        return serviceProvider;
    }
}