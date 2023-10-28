using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public static class GrayMintAuthenticationExtension
{
    public static AuthenticationBuilder AddGrayMintAuthentication(this AuthenticationBuilder authenticationBuilder,
        GrayMintAuthenticationOptions? authenticationOptions,
        bool isProduction)
    {
        if (authenticationOptions is null) throw new ArgumentNullException(nameof(authenticationOptions));
        authenticationOptions.Validate(isProduction);

        var securityKey = new SymmetricSecurityKey(authenticationOptions.Secret);
        authenticationBuilder
            .AddJwtBearer(GrayMintAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtRegisteredClaimNames.Email,
                    RequireSignedTokens = true,
                    IssuerSigningKey = securityKey,
                    ValidIssuer = authenticationOptions.Issuer,
                    ValidAudience = authenticationOptions.Audience ?? authenticationOptions.Issuer,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromSeconds(TokenValidationParameters.DefaultClockSkew.TotalSeconds)
                };
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
        authenticationBuilder.Services.AddScoped<GrayMintExternalAuthentication>();
        authenticationBuilder.Services.AddScoped<GrayMintTokenValidator>();
        authenticationBuilder.Services.AddScoped<GrayMintAuthentication>();
        return authenticationBuilder;
    }
}