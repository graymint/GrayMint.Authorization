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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GrayMint.Authorization;

public static class AuthorizationExtension
{
    public static WebApplicationBuilder AddGrayMintCommonAuthorizationForApp(this WebApplicationBuilder builder,
        GmRole[] roles,
        Action<DbContextOptionsBuilder> dbOptionsAction,
        string authenticationOptionsSectionName = "Auth",
        string teamControllerOptionsSectionName = "TeamController")
    {
        var authenticationOptions = builder.Configuration.GetSection(authenticationOptionsSectionName).Get<GrayMintAuthenticationOptions>()
            ?? throw new ArgumentException($"Could not read auth configuration from {authenticationOptionsSectionName}", nameof(authenticationOptionsSectionName));

        return builder.AddGrayMintCommonAuthorizationForApp(
                roles,
                dbOptionsAction,
                authenticationOptions,
                builder.Configuration.GetSection(teamControllerOptionsSectionName).Get<TeamControllerOptions>());
    }


    public static WebApplicationBuilder AddGrayMintCommonAuthorizationForApp(this WebApplicationBuilder builder,
        GmRole[] roles,
        Action<DbContextOptionsBuilder> dbOptionsAction,
        GrayMintAuthenticationOptions authenticationOptions,
        TeamControllerOptions? teamControllerOptions)
    {
        var services = builder.Services;

        // authentication & its controller
        services
            .AddGrayMintAuthenticationController()
            .AddAuthentication()
            .AddGrayMintAuthentication(authenticationOptions, builder.Environment.IsProduction());

        // authorization & its controller
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
        services
            .AddGrayMintUserProvider(
                new UserProviderOptions(), dbOptionsAction);

        // roles & its controller
        services
            .AddGrayMintTeamController(teamControllerOptions)
            .AddGrayMintRoleProvider(
                new RoleProviderOptions
                {
                    Roles = roles
                }, dbOptionsAction);

        return builder;
    }

    public static async Task UseGrayMinCommonAuthorizationForApp(this WebApplication webApplication)
    {
        webApplication.UseAuthentication();
        webApplication.UseAuthorization();
        await webApplication.Services.UseGrayMintUserProvider();
        await webApplication.Services.UseGrayMintRoleProvider();
    }
}