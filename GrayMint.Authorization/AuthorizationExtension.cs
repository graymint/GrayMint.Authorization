using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Controllers;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.RoleProviders;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers;
using GrayMint.Authorization.UserManagement.UserProviders;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GrayMint.Authorization;

public static class AuthorizationExtension
{
    public static void AddGrayMintFullAuthorization(this WebApplicationBuilder builder,
        GrayMintAuthenticationOptions authenticationOptions,
        TeamControllerOptions teamControllerOptions,
        GmRole[] roles,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        var services = builder.Services;

        // authentication
        services
            .AddGrayMintAuthenticationController()
            .AddAuthentication()
            .AddGrayMintAuthentication(authenticationOptions, builder.Environment.IsProduction());

        // authorization
        services
            .AddGrayMintRoleAuthorization()
            .AddAuthorization(options =>
            {
                // create default policy
                var policyBuilder = new AuthorizationPolicyBuilder();
                policyBuilder.RequireAuthenticatedUser();
                policyBuilder.AddAuthenticationSchemes(GrayMintAuthenticationDefaults.AuthenticationScheme);

                var defaultPolicy = policyBuilder.Build();
                options.AddPolicy("DefaultPolicy", defaultPolicy);
                options.DefaultPolicy = defaultPolicy;
            });
        
        // users
        services.AddGrayMintUserProvider(
            new UserProviderOptions
            {
                CacheTimeout = authenticationOptions.CacheTimeout
            }, dbOptionsAction);

        // roles
        services.AddGrayMintRoleProvider(
            new RoleProviderOptions
            {
                CacheTimeout = authenticationOptions.CacheTimeout,
                Roles = roles
            }, dbOptionsAction);

        services.AddGrayMintTeamController(teamControllerOptions);
    }

    public static async Task UseGrayMintFullAuthorization(this WebApplication webApplication)
    {
        await webApplication.Services.UseGrayMintUserProvider();
        await webApplication.Services.UseGrayMintRoleProvider();
    }
}