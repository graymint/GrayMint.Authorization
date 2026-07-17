using GrayMint.Authorization.Authentications.Controllers.Services;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications.Controllers;

public static class AuthenticationControllerExtension
{
    public static IServiceCollection AddGrayMintAuthenticationController(this IServiceCollection services,
        AuthenticationControllerOptions? options = null)
    {
        options ??= new AuthenticationControllerOptions();
        services.AddSingleton(Options.Create(options));
        services.AddScoped<AuthenticationService>();
        return services;
    }
}