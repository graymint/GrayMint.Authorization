using GrayMint.Authorization.Authentications.Controllers.Services;
using Microsoft.AspNetCore.Mvc;
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

        // without the endpoints the service's settings rule out: Google's sign-in, a user's own API key
        services.AddOptions<MvcOptions>()
            .Configure<IOptions<GrayMintAuthenticationOptions>>((mvcOptions, authenticationOptions) =>
                mvcOptions.Conventions.Add(new AuthenticationActionConvention(authenticationOptions.Value)));

        return services;
    }
}