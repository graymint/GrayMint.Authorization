using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

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

        authenticationBuilder.Services.AddSingleton(Options.Create(authenticationOptions));
        authenticationBuilder.Services.AddScoped<GrayMintTokenValidator>();
        authenticationBuilder.Services.AddScoped<GrayMintAuthentication>();
        return authenticationBuilder;
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