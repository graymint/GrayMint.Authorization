using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public static class RoleAuthorizationExtension
{
    public static IServiceCollection AddGrayMintRoleAuthorization(this IServiceCollection services,
        RoleAuthorizationOptions roleAuthOptions) 
    {
        // check duplicate roles
        services.AddAuthorization(options =>
        {
            // create default policy
            var policyBuilder = new AuthorizationPolicyBuilder();
            foreach(var scheme in roleAuthOptions.AuthenticationSchemes)
                policyBuilder.AddAuthenticationSchemes(scheme);

            policyBuilder.RequireAuthenticatedUser();
            var rolePolicy = policyBuilder.Build();
            options.AddPolicy(RoleAuthorization.Policy, rolePolicy);
            options.DefaultPolicy = rolePolicy;
        });

        services.AddSingleton(Options.Create(roleAuthOptions));
        services.AddScoped<IAuthorizationHandler, RoleAuthorizationHandler>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddScoped<RoleAuthorizationService>();
        services.AddTransient<IClaimsTransformation, RoleAuthorizationClaimsTransformation>();
        return services;
    }
}