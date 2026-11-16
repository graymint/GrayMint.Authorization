using GrayMint.Authorization.OpenIdAuthentications.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.OpenIdAuthentications;

// Reads the ID token a person's application got from a provider. A token counts only as the provider's own
// answer for one of this service's applications: signed by a key the provider publishes, in its name, not
// run out, meant for that application and asked for by one of them.
public sealed class OpenIdIdTokenReader(
    IOptions<OpenIdAuthenticationOptions> options,
    IOptionsMonitor<JwtBearerOptions> jwtBearerOptions)
{
    // null for anything else than such a token
    public async Task<OpenIdIdentity?> Read(string idToken, CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var issuer = ReadIssuer(handler, idToken);
        var provider = options.Value.Providers.FirstOrDefault(x => x.Issuer == issuer);
        if (provider == null)
            return null;

        // the keys the provider's own scheme reads and keeps, so they are asked for in one place
        var providerScheme = OpenIdAuthenticationDefaults.GetProviderScheme(provider.Name);
        var configurationManager = jwtBearerOptions.Get(providerScheme).ConfigurationManager ??
                                   throw new InvalidOperationException(
                                       $"The OpenID provider '{provider.Name}' has no source of its keys.");

        var configuration = await configurationManager.GetConfigurationAsync(cancellationToken);
        var result = await handler.ValidateTokenAsync(idToken, CreateParameters(provider, configuration.SigningKeys));

        // A provider lists a new key before it signs with it, but this service may not have looked since. The
        // keys are read again behind this request, which is turned away; the person's next try finds them. The
        // manager asks the provider only so often, so tokens nobody signed don't make it ask each time.
        if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
            configurationManager.RequestRefresh();

        if (!result.IsValid || result.SecurityToken is not JsonWebToken token || string.IsNullOrEmpty(token.Subject))
            return null;

        // an access token says what it is; one that names an application as its audience would pass the rest
        if (string.Equals(token.Typ, OpenIdAuthenticationDefaults.AccessTokenType, StringComparison.OrdinalIgnoreCase))
            return null;

        if (!IsAskedForByOwnApplication(token, provider))
            return null;

        // an id longer than the protocol allows is no account that could be tied
        if (token.Subject.Length > OpenIdDbContext.MaxSubjectLength)
            return null;

        return new OpenIdIdentity {
            ProviderName = provider.Name,
            Subject = token.Subject,
            Email = ReadClaim(token, JwtRegisteredClaimNames.Email),
            IsEmailVerified = string.Equals(ReadClaim(token, "email_verified"), "true", StringComparison.OrdinalIgnoreCase),
            Name = ReadClaim(token, JwtRegisteredClaimNames.Name)
        };
    }

    private static TokenValidationParameters CreateParameters(OpenIdProviderOptions provider,
        IEnumerable<SecurityKey> signingKeys)
    {
        return new TokenValidationParameters {
            ValidateIssuer = true,
            ValidIssuer = provider.Issuer,
            ValidateAudience = true,
            ValidAudiences = provider.ClientIds,

            // a name is read to its last letter: with one slash more it is another application's
            IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            ValidAlgorithms = provider.Algorithms,
            ClockSkew = OpenIdAuthenticationExtension.ClockSkew
        };
    }

    // A token says which application asked for it when it is meant for more than one, and may say so
    // anyway. That one must be this service's too: a token another application asked for is not the sign-in
    // of this service's person, though it names one of this service's applications beside its own.
    private static bool IsAskedForByOwnApplication(JsonWebToken token, OpenIdProviderOptions provider)
    {
        var authorizedParty = ReadClaim(token, JwtRegisteredClaimNames.Azp);
        return string.IsNullOrEmpty(authorizedParty)
            ? token.Audiences.Count() == 1
            : provider.ClientIds.Contains(authorizedParty);
    }

    // who the token says made it, before anything is checked: only to pick the provider that checks it
    private static string? ReadIssuer(JsonWebTokenHandler handler, string token)
    {
        try {
            return handler.CanReadToken(token) ? handler.ReadJsonWebToken(token).Issuer : null;
        }
        catch (Exception ex) when (ex is ArgumentException or SecurityTokenException) {
            return null;
        }
    }

    private static string? ReadClaim(JsonWebToken token, string type)
    {
        return token.TryGetClaim(type, out var claim) ? claim.Value : null;
    }
}
