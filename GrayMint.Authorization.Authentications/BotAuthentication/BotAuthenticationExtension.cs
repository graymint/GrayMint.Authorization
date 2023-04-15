using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications.BotAuthentication;

public static class BotAuthenticationExtension
{
    public static AuthenticationBuilder AddBotAuthentication(this AuthenticationBuilder authenticationBuilder,
        BotAuthenticationOptions? botAuthenticationOptions,
        bool isProduction)
    {
        if (botAuthenticationOptions is null) throw new ArgumentNullException(nameof(botAuthenticationOptions));
        botAuthenticationOptions.Validate(isProduction);

        var securityKey = new SymmetricSecurityKey(botAuthenticationOptions.BotKey);
        authenticationBuilder
            .AddJwtBearer(BotAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtRegisteredClaimNames.Email,
                    RequireSignedTokens = true,
                    IssuerSigningKey = securityKey,
                    ValidIssuer = botAuthenticationOptions.BotIssuer,
                    ValidAudience = botAuthenticationOptions.BotAudience ?? botAuthenticationOptions.BotIssuer,
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
                        var tokenValidator = scope.ServiceProvider.GetRequiredService<BotTokenValidator>();
                        await tokenValidator.Validate(context);
                    }
                };
            });

        authenticationBuilder.Services.AddSingleton(Options.Create(botAuthenticationOptions));
        authenticationBuilder.Services.AddScoped<BotTokenValidator>();
        authenticationBuilder.Services.AddScoped<BotAuthenticationTokenBuilder>();
        return authenticationBuilder;
    }
}