using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class GrayMintTokenValidator(
    IOptions<GrayMintAuthenticationOptions> authenticationOptions,
    IMemoryCache memoryCache,
    IAuthorizationProvider authorizationProvider,
    UserAuthorizationCache userAuthorizationCache)
{
    // what every copy of a token differs in; the rest is what an IAuthorizationProvider may read
    private static readonly HashSet<string> PerTokenClaimTypes = [
        JwtRegisteredClaimNames.Jti, JwtRegisteredClaimNames.Iat, JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf, GrayMintClaimTypes.AccessToken
    ];

    // a token's answers are cached by its claims, not its id, so the copies a refresh mints share one entry
    // instead of adding one each; the claims keep their order and all a provider may read of them (a FindFirst
    // tells orders apart), each part length-prefixed so no two sets read alike
    private static string BuildTokenCacheKey(ClaimsPrincipal claimsPrincipal)
    {
        var parts = claimsPrincipal.Claims
            .Where(x => !PerTokenClaimTypes.Contains(x.Type))
            .SelectMany(x => new[] { x.Type, x.ValueType, x.Issuer, x.Value })
            .Select(x => $"{x.Length}:{x}")
            .ToArray();

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Concat(parts))));
    }

    /// <param name="claimsPrincipal">Must have been already been validated</param>
    /// <param name="tokenUsage">the tokenUsage claim must be this value if it is not null</param>
    public async Task PostValidate(ClaimsPrincipal claimsPrincipal, string? tokenUsage = null)
    {
        if (claimsPrincipal.FindFirst(JwtRegisteredClaimNames.Jti) == null)
            throw new AuthenticationException("Can not find jti in token.");

        var tokenKey = BuildTokenCacheKey(claimsPrincipal);

        // translate name-identifier to userId
        var sub = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!string.IsNullOrEmpty(sub) && claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) != null)
            AuthorizationUtil.UpdateNameIdentifier(claimsPrincipal, sub);

        // get token version
        var tokenVersionStr = claimsPrincipal.Claims.SingleOrDefault(x => x.Type == GrayMintClaimTypes.Version)?.Value;
        var tokenVersion = tokenVersionStr != null ? int.Parse(tokenVersionStr) : 1;

        // check token usage
        if (tokenVersion > 1 && tokenUsage != null &&
            !claimsPrincipal.HasClaim(GrayMintClaimTypes.TokenUse, tokenUsage))
            throw new AuthenticationException(
                $"Can not authenticated by this token usage. RequiredToken: {tokenUsage}");

        // find the token's user; tied to the user once known, so a lock or a reset drops it; no user isn't kept
        var userIdCacheKey = $"graymint:auth:token:userid:{tokenKey}";
        var userId = await memoryCache.GetOrCreateAsync(userIdCacheKey, async entry => {
            entry.SetAbsoluteExpiration(authenticationOptions.Value.CacheTimeout);
            var id = await authorizationProvider.GetUserId(claimsPrincipal);
            if (id != null)
                userAuthorizationCache.AddUserItem(id, entry);
            else
                UserAuthorizationCache.RefuseEntry(entry);
            return id;
        });

        // check authCode: a token used for access carries the code it was issued with, so it can always be
        // revoked; only an id token of a user who has not signed up yet has none
        var tokenAuthCode = claimsPrincipal.Claims.SingleOrDefault(x => x.Type == GrayMintClaimTypes.AuthCode)?.Value;
        var isIdToken = tokenUsage != TokenUse.Access && claimsPrincipal.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id);
        if (tokenAuthCode == null && !isIdToken)
            throw new AuthenticationException($"Could not find {GrayMintClaimTypes.AuthCode} in the token.");

        if (tokenAuthCode != null && tokenAuthCode != AuthorizationConstants.AnyAuthCode) {
            if (string.IsNullOrEmpty(tokenAuthCode))
                throw new AuthenticationException($"Could not find {GrayMintClaimTypes.AuthCode} in the token.");

            // get authCode and manage cache; a user's code is tied to the user before it is read
            var authCode = userId != null
                ? await userAuthorizationCache.GetOrCreateUserItemAsync(userId, $"token:auth-code:{tokenKey}",
                    entry => CreateAuthCodeEntry(entry, claimsPrincipal))
                : await memoryCache.GetOrCreateAsync($"graymint:auth:token:auth-code:{tokenKey}",
                    entry => CreateAuthCodeEntry(entry, claimsPrincipal));

            if (string.IsNullOrEmpty(authCode))
                throw new AuthenticationException($"Could not find {GrayMintClaimTypes.AuthCode} in token.");

            if (authCode != tokenAuthCode)
                throw new AuthenticationException($"Invalid {GrayMintClaimTypes.AuthCode}.");
        }

        // update name-identifier
        if (userId != null)
            AuthorizationUtil.UpdateNameIdentifier(claimsPrincipal, userId);

        await authorizationProvider.OnAuthenticated(claimsPrincipal);
    }

    private async Task<string?> CreateAuthCodeEntry(ICacheEntry entry, ClaimsPrincipal claimsPrincipal)
    {
        entry.SetAbsoluteExpiration(authenticationOptions.Value.CacheTimeout);
        var authCode = await authorizationProvider.GetAuthorizationCode(claimsPrincipal);

        // no code isn't kept: the check fails on it anyway, and the tokens of a user gone would each keep one
        if (string.IsNullOrEmpty(authCode))
            UserAuthorizationCache.RefuseEntry(entry);

        return authCode;
    }

    private static string EnsureHttps(string url)
    {
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            url = "https://" + url;
        return url;
    }

    private Task<OpenIdConnectConfiguration> GetOpenIdConnectConfigurationByIssuer(string issuer)
    {
        issuer = EnsureHttps(issuer);
        return GetOpenIdConnectConfiguration($"{issuer}/.well-known/openid-configuration");
    }

    private async Task<OpenIdConnectConfiguration> GetOpenIdConnectConfiguration(string url)
    {
        var openIdConfig = await memoryCache.GetOrCreateAsync(url, entry => {
            var configurationManager =
                new ConfigurationManager<OpenIdConnectConfiguration>(url, new OpenIdConnectConfigurationRetriever());
            entry.SetAbsoluteExpiration(authenticationOptions.Value.OpenIdConfigTimeout);
            return configurationManager.GetConfigurationAsync();
        }) ?? throw new AuthenticationException($"Could not retrieve OpenId config. EndPoint: {url}");

        return openIdConfig;
    }

    public async Task<ClaimsIdentity> ValidateOpenIdToken(string idToken, OpenIdProvider openIdProvider)
    {
        // Set the parameters for token validation
        var issuer = openIdProvider.Issuer ?? openIdProvider.Issuers.FirstOrDefault() ??
            throw new Exception($"Could not find any issuer for {openIdProvider.Name}");
        var openIdConfig = await GetOpenIdConnectConfigurationByIssuer(issuer);
        var validationParameters = new TokenValidationParameters {
            ValidateIssuer = true,
            ValidIssuer = openIdProvider.Issuer,
            ValidIssuers = openIdProvider.Issuers,
            ValidateAudience = true,
            ValidAudience = openIdProvider.Audience,
            ValidAudiences = openIdProvider.Audiences,
            ValidateLifetime = true,
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ValidateIssuerSigningKey = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.ValidateToken(idToken, validationParameters, out var token);
        var jwtToken = (JwtSecurityToken)token;
        var claimsIdentity = new ClaimsIdentity(jwtToken.Claims);

        // check if this token is an id token
        if (claimsIdentity.HasClaim(x => x.Type is JwtRegisteredClaimNames.Email or JwtRegisteredClaimNames.Name))
            ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.TokenUse, TokenUse.Id));

        return claimsIdentity;
    }

    public async Task<ClaimsIdentity> ValidateGrayMintToken(string token)
    {
        try {
            // Set the parameters for token validation
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = GrayMintAuthentication.GetTokenValidationParameters(authenticationOptions.Value);
            var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
            await PostValidate(claimsPrincipal);

            var claimIdentity = new ClaimsIdentity(claimsPrincipal.Claims);
            return claimIdentity;
        }
        catch (SecurityTokenException ex) {
            // Handle specific security token exceptions and
            // convert them to AuthenticationException
            throw new AuthenticationException(ex.Message, ex);
        }
    }

    private OpenIdProvider? FindOpenIdProvider(string issuer)
    {
        return authenticationOptions.Value.OpenIdProviders
            .SingleOrDefault(x => x.Issuer == issuer || x.Issuers.Contains(issuer));
    }

    // an identity provider's id token only, never one of ours
    public async Task<ClaimsIdentity> ValidateOpenIdToken(string idToken)
    {
        try {
            var issuer = new JwtSecurityTokenHandler().ReadToken(idToken).Issuer;
            var openIdProvider = FindOpenIdProvider(issuer)
                                 ?? throw new AuthenticationException(
                                     $"Could not find any provider for this issuer. {issuer}");

            var claimsIdentity = await ValidateOpenIdToken(idToken, openIdProvider);
            if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
                throw new AuthenticationException("This is not an id token.");

            return claimsIdentity;
        }
        catch (Exception ex) {
            throw new AuthenticationException(ex.Message);
        }
    }

    public virtual async Task<ClaimsIdentity> ValidateIdToken(string idToken)
    {
        try {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(idToken);

            ClaimsIdentity claimsIdentity;
            var openIdProvider = FindOpenIdProvider(securityToken.Issuer);

            if (openIdProvider != null)
                claimsIdentity = await ValidateOpenIdToken(idToken, openIdProvider);

            else if (securityToken.Issuer == authenticationOptions.Value.Issuer)
                claimsIdentity = await ValidateGrayMintToken(idToken);

            else
                throw new AuthenticationException(
                    $"Could not find any provider for this issuer. {securityToken.Issuer}");

            // check if this token is an id token
            if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
                throw new AuthenticationException("This is not an id token.");

            return claimsIdentity;
        }
        catch (Exception ex) {
            throw new AuthenticationException(ex.Message);
        }
    }
}