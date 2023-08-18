using GrayMint.Authorization.PermissionAuthorizations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public static class RoleAuthorizationExtension
{
    public static IServiceCollection AddGrayMintRoleAuthorization(this IServiceCollection services) 
    {
        // make sure PermissionAuthorization is added before RoleAuthorization
        if (services.Any(x => x.ServiceType == typeof(IAuthorizationHandler) && x.ImplementationType==typeof(PermissionAuthorizationHandler) ))
            throw new InvalidOperationException($"{nameof(PermissionAuthorization)} should not be added before {nameof(RoleAuthorization)}.");

        services.AddScoped<IAuthorizationHandler, RolePermissionsAuthorizationHandler>();
        services.AddTransient<IClaimsTransformation, RoleAuthorizationClaimsTransformation>();
        services.AddGrayMintPermissionAuthorization();
        return services;
    }
}