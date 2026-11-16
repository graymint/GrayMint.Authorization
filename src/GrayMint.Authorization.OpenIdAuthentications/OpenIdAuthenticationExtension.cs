using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.OpenIdAuthentications.Persistence;
using GrayMint.Common.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.OpenIdAuthentications;

public static class OpenIdAuthenticationExtension
{
    // how far the clocks of the provider and this service may be apart
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    private const string BearerPrefix = "Bearer ";

    // Takes the access tokens of the configured providers. Each provider has a scheme of its own, which
    // checks a token by that provider's published keys alone; the scheme a service names hands a request to
    // the provider its token names. A caller is authenticated only as the user its account is tied to.
    public static AuthenticationBuilder AddGrayMintOpenIdAuthentication(this AuthenticationBuilder builder,
        OpenIdAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        builder.AddPolicyScheme(OpenIdAuthenticationDefaults.AuthenticationScheme, displayName: null,
            policy => policy.ForwardDefaultSelector = httpContext => SelectProviderScheme(httpContext, options));

        foreach (var provider in options.Providers)
            builder.AddJwtBearer(OpenIdAuthenticationDefaults.GetProviderScheme(provider.Name),
                bearer => ConfigureProvider(bearer, provider));

        builder.Services.AddMemoryCache();
        builder.Services.AddSingleton<UserAuthorizationCache>();
        builder.Services.AddSingleton(Options.Create(options));
        builder.Services.AddSingleton<OpenIdIdTokenReader>();
        builder.Services.AddScoped<UserBindingStore>();
        builder.Services.AddScoped<OpenIdUserResolver>();
        builder.Services.AddScoped<OpenIdSignInService>();
        return builder;
    }

    public static IServiceCollection AddGrayMintOpenIdAuthenticationDb(this IServiceCollection services,
        Action<DbContextOptionsBuilder> dbOptionsAction)
    {
        services.AddDbContext<OpenIdDbContext>(dbOptionsAction);
        return services;
    }

    // makes the tables where they are missing; a service whose database login may not, leaves that to its setup
    public static async Task<IServiceProvider> UseGrayMintOpenIdAuthentication(this IServiceProvider serviceProvider)
    {
        await using var scope = serviceProvider.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<OpenIdDbContext>();
        await EfCoreUtil.EnsureTablesCreated(dbContext.Database);
        return serviceProvider;
    }

    private static void ConfigureProvider(JwtBearerOptions bearer, OpenIdProviderOptions provider)
    {
        // the provider's keys are read from its own address, and again when a token names one that isn't here
        bearer.Authority = provider.Issuer;
        bearer.RequireHttpsMetadata = !provider.AllowInsecureHttp;

        // Claims stay as the token names them. Renamed the old way, an address in a token would become the
        // claim that a provider of users finds a user by.
        bearer.MapInboundClaims = false;
        bearer.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuer = true,
            ValidIssuer = provider.Issuer,
            ValidateAudience = true,
            ValidAudience = provider.Audience,

            // a name is read to its last letter: with one slash more it is another service's
            IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = provider.Algorithms,

            // an ID token of the same provider is signed by the same keys, and is no key to this service
            ValidTypes = [OpenIdAuthenticationDefaults.AccessTokenType],
            ClockSkew = ClockSkew
        };

        bearer.Events = new JwtBearerEvents {
            OnTokenValidated = async context => {
                var principal = context.Principal ??
                                throw new InvalidOperationException("The checked token has no principal.");
                var resolver = context.HttpContext.RequestServices.GetRequiredService<OpenIdUserResolver>();
                if (!await resolver.TryResolve(provider.Name, principal, context.HttpContext.RequestAborted))
                    context.Fail("The account is tied to no user of this service.");
            }
        };
    }

    // The provider that the request's token names, before anything is checked: its scheme does the checking,
    // by its own keys. A token that names none goes to the first, which refuses it.
    private static string SelectProviderScheme(HttpContext httpContext, OpenIdAuthenticationOptions options)
    {
        var issuer = ReadIssuer(httpContext.Request.Headers.Authorization.ToString());
        var provider = options.Providers.FirstOrDefault(x => x.Issuer == issuer) ?? options.Providers[0];
        return OpenIdAuthenticationDefaults.GetProviderScheme(provider.Name);
    }

    private static string? ReadIssuer(string authorization)
    {
        if (!authorization.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
            return null;

        var token = authorization[BearerPrefix.Length..].Trim();
        var handler = new JsonWebTokenHandler();
        try {
            return handler.CanReadToken(token) ? handler.ReadJsonWebToken(token).Issuer : null;
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException) {
            return null;
        }
    }
}
