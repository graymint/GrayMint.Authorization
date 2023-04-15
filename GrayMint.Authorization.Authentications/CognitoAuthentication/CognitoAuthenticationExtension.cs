using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications.CognitoAuthentication;

public static class CognitoAuthenticationExtension
{
    public static AuthenticationBuilder AddCognitoAuthentication(this AuthenticationBuilder authenticationBuilder, CognitoAuthenticationOptions? cognitoOptions)
    {
        if (cognitoOptions == null) throw new ArgumentNullException(nameof(cognitoOptions));
        cognitoOptions.Validate();

        authenticationBuilder
            .AddJwtBearer(CognitoAuthenticationDefaults.AuthenticationScheme, options =>
            {
                var cognitoArn = new AwsArn(cognitoOptions.CognitoArn);
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = JwtRegisteredClaimNames.Email,
                    ValidIssuer = cognitoOptions.CognitoArn,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateAudience = false,
                };
                options.MetadataAddress = $"https://{cognitoArn.Service}.{cognitoArn.Region}.amazonaws.com/{cognitoArn.ResourceId}/.well-known/openid-configuration";

                options.SaveToken = true;

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        await using var scope = context.HttpContext.RequestServices.CreateAsyncScope();
                        var tokenValidator = scope.ServiceProvider.GetRequiredService<CognitoTokenValidator>();
                        await tokenValidator.Validate(context);
                    }
                };
            });

        authenticationBuilder.Services.AddSingleton<CognitoTokenValidator>();
        authenticationBuilder.Services.AddSingleton(Options.Create(cognitoOptions));
        return authenticationBuilder;
    }
}