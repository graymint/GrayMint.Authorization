using GrayMint.Authorization.RoleManagement.RoleControllers.Services;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.RoleControllers;

public static class RoleControllerExtension
{
    public static void AddGrayMintRoleController(this IServiceCollection services,
        RoleControllerOptions? options = null)
    {
        options ??= new RoleControllerOptions();
        services.AddSingleton(Options.Create(options));
        services.AddScoped<RoleService>();
    }
}