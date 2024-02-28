using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class GrayMintTokenValidator
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly IMemoryCache _memoryCache;
    private readonly UserAuthorizationCache _userAuthorizationCache;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;

    public GrayMintTokenValidator(
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        IMemoryCache memoryCache,
        IAuthorizationProvider authorizationProvider,
        UserAuthorizationCache userAuthorizationCache)
    {
        _memoryCache = memoryCache;
        _authorizationProvider = authorizationProvider;
        _userAuthorizationCache = userAuthorizationCache;
        _authenticationOptions = authenticationOptions.Value;
    }

    /// <param name="claimsPrincipal">Must have been already been validated</param>
    /// <param name="tokenUsage">the tokenUsage claim must be this value if it is not null</param>
    public async Task PostValidate(ClaimsPrincipal claimsPrincipal, string? tokenUsage = null)
    {
        var tokenId = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Jti)
                      ?? throw new AuthenticationException("Can not find jti in token.");

        // translate name-identifier to userId
        var sub = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (!string.IsNullOrEmpty(sub) && claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier) != null)
            AuthorizationUtil.UpdateNameIdentifier(claimsPrincipal, sub);

        // get token version
        var tokenVersionStr = claimsPrincipal.Claims.SingleOrDefault(x => x.Type == GrayMintClaimTypes.Version)?.Value;
        var tokenVersion = tokenVersionStr != null ? int.Parse(tokenVersionStr) : 1;

        // check token usage
        if (tokenVersion > 1 && tokenUsage != null && !claimsPrincipal.HasClaim(GrayMintClaimTypes.TokenUse, tokenUsage))
            throw new AuthenticationException($"Can not authenticated by this token usage. RequiredToken: {tokenUsage}");

        // check authCode
        var tokenAuthCode = claimsPrincipal.Claims.SingleOrDefault(x => x.Type == GrayMintClaimTypes.AuthCode)?.Value;
        var authCodeCacheKey = $"graymint:auth:token:auth-code:jti={tokenId}";
        if (tokenAuthCode != null && tokenAuthCode != AuthorizationConstants.AnyAuthCode)
        {
            if (string.IsNullOrEmpty(tokenAuthCode))
                throw new AuthenticationException($"Could not find {GrayMintClaimTypes.AuthCode} in the token.");

            // get authCode and manage cache
            var authCode = await _memoryCache.GetOrCreateAsync(authCodeCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_authenticationOptions.CacheTimeout);
                return _authorizationProvider.GetAuthorizationCode(claimsPrincipal);
            });

            if (string.IsNullOrEmpty(authCode))
                throw new AuthenticationException($"Could not find {GrayMintClaimTypes.AuthCode} in token.");

            if (authCode != tokenAuthCode)
                throw new AuthenticationException($"Invalid {GrayMintClaimTypes.AuthCode}.");
        }

        // update name-identifier
        var userIdCacheKey = $"graymint:auth:token:userid:jti={tokenId}";
        var userId = await _memoryCache.GetOrCreateAsync(userIdCacheKey, entry =>
        {
            entry.SetAbsoluteExpiration(_authenticationOptions.CacheTimeout);
            return _authorizationProvider.GetUserId(claimsPrincipal);
        });

        if (userId != null)
        {
            AuthorizationUtil.UpdateNameIdentifier(claimsPrincipal, userId);
            _userAuthorizationCache.AddUserItem(userId, userIdCacheKey);
            _userAuthorizationCache.AddUserItem(userId, authCodeCacheKey);
        }

        await _authorizationProvider.OnAuthenticated(claimsPrincipal);
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
        var openIdConfig = await _memoryCache.GetOrCreateAsync(url, entry =>
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(url, new OpenIdConnectConfigurationRetriever());
            entry.SetAbsoluteExpiration(_authenticationOptions.OpenIdConfigTimeout);
            return configurationManager.GetConfigurationAsync();
        }) ?? throw new AuthenticationException($"Could not retrieve OpenId config. EndPoint: {url}");

        return openIdConfig;
    }

    public async Task<ClaimsIdentity> ValidateOpenIdToken(string idToken, OpenIdProvider openIdProvider)
    {
        // Set the parameters for token validation
        var openIdConfig = await GetOpenIdConnectConfigurationByIssuer(openIdProvider.Issuer);
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = openIdProvider.Issuer,
            ValidIssuers = openIdProvider.Issuers,
            ValidateAudience = true,
            ValidAudience = openIdProvider.Audience,
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
        // Set the parameters for token validation
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = GrayMintAuthentication.GetTokenValidationParameters(_authenticationOptions);
        var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
        await PostValidate(claimsPrincipal);

        var claimIdentity = new ClaimsIdentity(claimsPrincipal.Claims);
        return claimIdentity;
    }

    public virtual async Task<ClaimsIdentity> ValidateIdToken(string idToken)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(idToken);

            ClaimsIdentity claimsIdentity;
            var openIdProvider = _authenticationOptions.OpenIdProviders
                .SingleOrDefault(x => x.Issuer == securityToken.Issuer || x.Issuers.Contains(securityToken.Issuer));

            if (openIdProvider != null)
                claimsIdentity = await ValidateOpenIdToken(idToken, openIdProvider);

            else if (securityToken.Issuer == _authenticationOptions.Issuer)
                claimsIdentity = await ValidateGrayMintToken(idToken);

            else
                throw new AuthenticationException($"Could not find any provider for this issuer. {securityToken.Issuer}");

            // check if this token is an id token
            if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
                throw new AuthenticationException("This is not an id token.");

            return claimsIdentity;
        }
        catch (Exception ex)
        {
            throw new AuthenticationException(ex.Message);
        }
    }
}