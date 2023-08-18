using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

public static class PermissionAuthorizationExtension
{
    public static IServiceCollection AddGrayMintPermissionAuthorization(this IServiceCollection services) 
    {
        // check if PermissionAuthorizationHandler is not already added and add it if not
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        return services;
    }
}