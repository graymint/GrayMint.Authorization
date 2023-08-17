using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

public static class PermissionAuthorizationExtension
{
    public static IServiceCollection AddGrayMintPermissionAuthorization(
        this IServiceCollection services, 
        PermissionAuthorizationOptions permissionOptions) 
    {

        // check duplicate roles
        services.AddAuthorization(options =>
        {
            foreach (var permission in permissionOptions.Permissions)
            {
                var policyBuilder = new AuthorizationPolicyBuilder();
                policyBuilder.RequireAuthenticatedUser();
                policyBuilder.AddRequirements(new PermissionAuthorizationRequirement
                {
                    Permission = permission,
                    ResourceRouteName = permissionOptions.ResourceRouteName,
                    ResourceValuePrefix = permissionOptions.ResourceValuePrefix
                });
                options.AddPolicy(PermissionAuthorization.BuildPermissionPolicyName(permission), policyBuilder.Build());
            }
        });

        // check if PermissionAuthorizationHandler is not already added and add it if not
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        return services;
    }
}