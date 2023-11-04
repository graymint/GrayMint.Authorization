using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications;

public static class GrayMintAuthenticationExtension
{
    public static AuthenticationBuilder AddGrayMintAuthentication(this AuthenticationBuilder authenticationBuilder,
        GrayMintAuthenticationOptions? authenticationOptions,
        bool isProduction)
    {
        if (authenticationOptions is null) throw new ArgumentNullException(nameof(authenticationOptions));
        authenticationOptions.Validate(isProduction);

        authenticationBuilder
            .AddJwtBearer(GrayMintAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = GrayMintAuthentication.GetTokenValidationParameters(authenticationOptions);
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        await using var scope = context.HttpContext.RequestServices.CreateAsyncScope();
                        var tokenValidator = scope.ServiceProvider.GetRequiredService<GrayMintTokenValidator>();
                        await tokenValidator.Validate(context);
                    }
                };
            });

        authenticationBuilder.Services.AddSingleton(Options.Create(authenticationOptions));
        authenticationBuilder.Services.AddScoped<GrayMintIdTokenValidator>();
        authenticationBuilder.Services.AddScoped<GrayMintTokenValidator>();
        authenticationBuilder.Services.AddScoped<GrayMintAuthentication>();
        return authenticationBuilder;
    }
}