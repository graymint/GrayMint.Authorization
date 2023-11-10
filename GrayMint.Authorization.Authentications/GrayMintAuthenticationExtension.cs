using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Abstractions;
using System.ComponentModel;

namespace GrayMint.Authorization.Authentications;

public static class GrayMintAuthenticationExtension
{
    public static AuthenticationBuilder AddGrayMintAuthentication(this AuthenticationBuilder builder,
        GrayMintAuthenticationOptions authenticationOptions,
        bool isProduction)
    {
        ArgumentNullException.ThrowIfNull(authenticationOptions);
        authenticationOptions.Validate(isProduction);

        builder
            .AddJwtBearer(GrayMintAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = GrayMintAuthentication.GetTokenValidationParameters(authenticationOptions);
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        await using var scope = context.HttpContext.RequestServices.CreateAsyncScope();
                        var tokenValidator = scope.ServiceProvider.GetRequiredService<GrayMintTokenValidator>();
                        AddTokenIdIfNotExists(context);
                        try
                        {
                            var principal = context.Principal ?? throw new AuthenticationException("Principal has not been validated.");
                            await tokenValidator.PostValidate(principal, TokenUse.Access);
                        }
                        catch (Exception ex)
                        {
                            context.Fail(ex.Message);
                        }
                    }
                };
            });

        builder.Services.AddSingleton<UserAuthorizationCache>();
        builder.Services.AddSingleton(Options.Create(authenticationOptions));
        builder.Services.AddScoped<GrayMintTokenValidator>();
        builder.Services.AddScoped<GrayMintAuthentication>();
        return builder;
    }

    // todo: for compatibility
    private static void AddTokenIdIfNotExists(TokenValidatedContext context)
    {
        if (context.Principal == null || context.Principal.FindFirstValue(JwtRegisteredClaimNames.Jti) != null)
            return;

        var tokenRawData = ((JwtSecurityToken)context.SecurityToken).RawData;
        var hashBytes = MD5.HashData(Encoding.UTF8.GetBytes(tokenRawData));
        var tokenId = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Jti, tokenId));
        context.Principal.AddIdentity(claimsIdentity);
    }

}