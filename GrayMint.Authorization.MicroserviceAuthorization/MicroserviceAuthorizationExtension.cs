using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.PermissionAuthorizations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace GrayMint.Authorization.MicroserviceAuthorization;

public static class MicroserviceAuthorizationExtension
{
    public static WebApplicationBuilder AddGrayMintCommonAuthorizationForMicroservice<TAuthorizationProvider>(
        this WebApplicationBuilder builder,
        string authenticationOptionsSectionName = "Auth")
        where TAuthorizationProvider : class, IAuthorizationProvider
    {
        var authenticationOptions = builder.Configuration.GetSection(authenticationOptionsSectionName).Get<GrayMintAuthenticationOptions>()
            ?? throw new ArgumentException($"Could not read auth configuration from {authenticationOptionsSectionName}", nameof(authenticationOptionsSectionName));

        return builder.AddGrayMintCommonAuthorizationForMicroservice<TAuthorizationProvider>(
                authenticationOptions);
    }

    public static WebApplicationBuilder AddGrayMintCommonAuthorizationForMicroservice<TAuthorizationProvider>(
        this WebApplicationBuilder builder,
        GrayMintAuthenticationOptions authenticationOptions)
        where TAuthorizationProvider : class, IAuthorizationProvider
    {
        var services = builder.Services;

        // add authentication
        builder.Services
            .AddAuthentication()
            .AddGrayMintAuthentication(authenticationOptions, builder.Environment.IsProduction());

        // support permission authorization
        builder.Services.AddGrayMintPermissionAuthorization();

        // add Authorization
        builder.Services.AddAuthorization(options =>
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
            .AddScoped<IAuthorizationProvider, TAuthorizationProvider>()
            .AddScoped<MicroserviceAuthorizationService>();

        return builder;
    }

    public static Task UseGrayMinCommonAuthorizationForMicroservice(this WebApplication webApplication)
    {
        webApplication.UseAuthentication();
        webApplication.UseAuthorization();
        return Task.CompletedTask;
    }

}