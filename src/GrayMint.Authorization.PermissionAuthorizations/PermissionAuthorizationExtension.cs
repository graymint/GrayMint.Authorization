using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

public static class PermissionAuthorizationExtension
{
    public static IServiceCollection AddGrayMintPermissionAuthorization(this IServiceCollection services)
    {
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        return services;
    }
}