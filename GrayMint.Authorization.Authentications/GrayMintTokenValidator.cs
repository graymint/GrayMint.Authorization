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
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly IMemoryCache _memoryCache;

    public GrayMintTokenValidator(
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        IMemoryCache memoryCache,
        IAuthorizationProvider authorizationProvider)
    {
        _memoryCache = memoryCache;
        _authorizationProvider = authorizationProvider;
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
        if (tokenVersion > 1 && tokenUsage!=null && !claimsPrincipal.HasClaim(GrayMintClaimTypes.TokenUse, tokenUsage))
            throw new AuthenticationException($"Can not authenticated by this token usage. RequiredToken: {tokenUsage}");

        // check authCode
        var tokenAuthCode = claimsPrincipal.Claims.SingleOrDefault(x => x.Type == GrayMintAuthenticationDefaults.AuthorizationCodeTypeName)?.Value;
        var authCodeCacheKey = $"graymint:auth:token:auth-code:jti={tokenId}";
        if (tokenAuthCode != null && tokenAuthCode != AuthorizationConstants.AnyAuthCode)
        {
            if (string.IsNullOrEmpty(tokenAuthCode))
                throw new AuthenticationException($"Could not find {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName} in the token.");

            // get authCode and manage cache
            var authCode = await _memoryCache.GetOrCreateAsync(authCodeCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_authenticationOptions.CacheTimeout);
                return _authorizationProvider.GetAuthorizationCode(claimsPrincipal);
            });

            if (string.IsNullOrEmpty(authCode))
                throw new AuthenticationException($"Could not find {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName} in token.");

            if (authCode != tokenAuthCode)
                throw new AuthenticationException($"Invalid {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName}.");
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
            AuthorizationCache.AddKey(_memoryCache, userId, userIdCacheKey);
            AuthorizationCache.AddKey(_memoryCache, userId, authCodeCacheKey);
        }

        await _authorizationProvider.OnAuthenticated(claimsPrincipal);
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

    private static void AddClaim(JwtPayload source, ClaimsIdentity destination, string sourceType,
        string? destinationType = null, string? destinationValueType = null)
    {
        foreach (var claim in source.Claims.Where(x => x.Type == sourceType))
            destination.AddClaim(new Claim(destinationType ?? sourceType, claim.Value, destinationValueType ?? claim.ValueType));
    }

    private static void AddKnownClaims(JwtPayload source, ClaimsIdentity destination)
    {
        AddClaim(source, destination, JwtRegisteredClaimNames.Sub);
        AddClaim(source, destination, JwtRegisteredClaimNames.Name);
        AddClaim(source, destination, JwtRegisteredClaimNames.GivenName);
        AddClaim(source, destination, JwtRegisteredClaimNames.FamilyName);
        AddClaim(source, destination, JwtRegisteredClaimNames.Email);
        AddClaim(source, destination, JwtRegisteredClaimNames.AuthTime);
        AddClaim(source, destination, GrayMintClaimTypes.EmailVerified);
        AddClaim(source, destination, GrayMintClaimTypes.Nonce);
        AddClaim(source, destination, GrayMintClaimTypes.Picture);
        AddClaim(source, destination, GrayMintClaimTypes.CognitoGroup);
        AddClaim(source, destination, GrayMintClaimTypes.TokenUse);
        AddClaim(source, destination, GrayMintClaimTypes.LongExpiration);
    }

    public async Task<ClaimsIdentity> ValidateCognitoToken(string idToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.CognitoArn);
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.CognitoClientId);

        var cognitoArn = new AwsArn(_authenticationOptions.CognitoArn);
        var metaDataUrl = $"https://{cognitoArn.Service}.{cognitoArn.Region}.amazonaws.com/{cognitoArn.ResourceId}/.well-known/openid-configuration";
        var openIdConfig = await GetOpenIdConnectConfiguration(metaDataUrl);

        // Set the parameters for token validation
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = openIdConfig.Issuer,
            ValidateAudience = true,
            ValidAudience = _authenticationOptions.CognitoClientId,
            ValidateLifetime = true,
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ValidateIssuerSigningKey = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.ValidateToken(idToken, validationParameters, out var token);
        var jwtToken = (JwtSecurityToken)token;
        var jwtPayload = jwtToken.Payload;

        var claimsIdentity = new ClaimsIdentity();
        AddKnownClaims(jwtPayload, claimsIdentity);
        return claimsIdentity;
    }

    public async Task<ClaimsIdentity> ValidateGoogleIdToken(string idToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.GoogleClientId);

        const string metaDataUrl = "https://accounts.google.com/.well-known/openid-configuration";
        var openIdConfig = await GetOpenIdConnectConfiguration(metaDataUrl);

        // Set the parameters for token validation
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = openIdConfig.Issuer,
            ValidateAudience = true,
            ValidAudience = _authenticationOptions.GoogleClientId,
            ValidateLifetime = true,
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ValidateIssuerSigningKey = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.ValidateToken(idToken, validationParameters, out var token);
        var jwtToken = (JwtSecurityToken)token;
        var jwtPayload = jwtToken.Payload;

        // check if this token is an id token
        var claimsIdentity = new ClaimsIdentity();
        AddKnownClaims(jwtPayload, claimsIdentity);

        if (jwtPayload.Any(x => x.Key == JwtRegisteredClaimNames.Email))
            claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.TokenUse, TokenUse.Id));

        return claimsIdentity;

    }

    public async Task<ClaimsIdentity> ValidateGrayMintToken(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.GoogleClientId);

        // Set the parameters for token validation
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = GrayMintAuthentication.GetTokenValidationParameters(_authenticationOptions);
        var claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out var securityToken);
        await PostValidate(claimsPrincipal);

        var jwtToken = (JwtSecurityToken)securityToken;
        var jwtPayload = jwtToken.Payload;

        var claimsIdentity = new ClaimsIdentity();
        AddKnownClaims(jwtPayload, claimsIdentity);
        return claimsIdentity;
    }

    public virtual async Task<ClaimsIdentity> ValidateIdToken(string idToken)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(idToken);

            ClaimsIdentity claimsIdentity;

            if (securityToken.Issuer.Contains(".amazonaws.com"))
                claimsIdentity = await ValidateCognitoToken(idToken);

            else if (securityToken.Issuer.Contains(".google.com"))
                claimsIdentity = await ValidateGoogleIdToken(idToken);

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