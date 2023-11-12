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
    private readonly UserAuthorizationCache _userAuthorizationCache;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly IMemoryCache _memoryCache;

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

    /// <param name="claimsPrincipal">Must has been already validated</param>
    /// <param name="tokenUsage">the tokenUsage claim must be this value if it is not null</param>
    public async Task PostValidate(ClaimsPrincipal claimsPrincipal, string? tokenUsage = null)
    {
        var tokenId = claimsPrincipal.FindFirstValue(JwtRegisteredClaimNames.Jti)
                      ?? throw new AuthenticationException("Can not find jti in token.");

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

    private Task<OpenIdConnectConfiguration> GetOpenIdConnectConfigurationByIssuer(string issuer)
    {
        return GetOpenIdConnectConfiguration($"{issuer}/.well-known/openid-configuration");
    }

    private async Task<OpenIdConnectConfiguration> GetOpenIdConnectConfiguration(string url)
    {
        var openIdConfig = await _memoryCache.GetOrCreateAsync(url, async entry =>
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(url, new OpenIdConnectConfigurationRetriever());
            entry.SetAbsoluteExpiration(_authenticationOptions.OpenIdConfigTimeout);
            return await configurationManager.GetConfigurationAsync();
        }) ?? throw new AuthenticationException($"Could not retrieve OpenId config. EndPoint: {url}");

        return openIdConfig;
    }

    public async Task<ClaimsIdentity> ValidateOpenIdToken(string idToken, string issuer, string audience)
    {
        // Set the parameters for token validation
        var openIdConfig = await GetOpenIdConnectConfigurationByIssuer(issuer);
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = openIdConfig.Issuer,
            ValidateAudience = true,
            ValidAudience = audience,
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
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.GoogleClientId);

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

            if (securityToken.Issuer.Contains(".amazonaws.com"))
                claimsIdentity = await ValidateOpenIdToken(idToken, securityToken.Issuer,
                    _authenticationOptions.CognitoClientId ?? throw new AuthenticationException("CognitoClientId has not been set."));

            else if (securityToken.Issuer.Contains("https://securetoken.google.com/"))
                claimsIdentity = await ValidateOpenIdToken(idToken, securityToken.Issuer,
                    _authenticationOptions.FirebaseProjectId ?? throw new AuthenticationException("FirebaseProjectId has not been set."));

            else if (securityToken.Issuer.Contains(".google.com"))
                claimsIdentity = await ValidateOpenIdToken(idToken, securityToken.Issuer,
                    _authenticationOptions.GoogleClientId ?? throw new AuthenticationException("GoogleClientId has not been set."));

            else if (securityToken.Issuer == _authenticationOptions.Issuer)
                claimsIdentity = await ValidateGrayMintToken(idToken);

            else
                throw new AuthenticationException("Could not find any provider for this token.");

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