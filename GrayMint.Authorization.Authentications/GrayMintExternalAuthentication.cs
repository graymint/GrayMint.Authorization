using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class GrayMintExternalAuthentication
{
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly IMemoryCache _memoryCache;

    public GrayMintExternalAuthentication(
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
        _authenticationOptions = authenticationOptions.Value;
    }

    private async Task<OpenIdConnectConfiguration> GetOpenIdConnectConfiguration(string url)
    {
        var openIdConfig = await _memoryCache.GetOrCreateAsync(url, async entry =>
        {
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(url, new OpenIdConnectConfigurationRetriever());
            entry.SetAbsoluteExpiration(_authenticationOptions.OpenIdConfigTimeout);
            return await configurationManager.GetConfigurationAsync();
        }) ?? throw new Exception($"Could not retrieve OpenId config. EndPoint: {url}");

        return openIdConfig;
    }

    private static void AddClaim(JwtPayload source, ClaimsIdentity destination, string sourceType,
        string? destinationType = null, string? destinationValueType = null)
    {
        foreach (var claim in source.Claims.Where(x => x.Type == sourceType))
            destination.AddClaim(new Claim(destinationType ?? sourceType, claim.Value, destinationValueType ?? claim.ValueType));
    }

    public async Task<ClaimsIdentity> GetClaimsIdentityFromCognito(string idToken)
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
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.Name);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.GivenName);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.FamilyName);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.Email);
        AddClaim(jwtPayload, claimsIdentity, "email_verified");
        AddClaim(jwtPayload, claimsIdentity, "nonce");
        AddClaim(jwtPayload, claimsIdentity, "picture");
        AddClaim(jwtPayload, claimsIdentity, "cognito:groups");

        return claimsIdentity;
    }

    public async Task<ClaimsIdentity> GetClaimsIdentityFromGoogle(string idToken)
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

        var claimsIdentity = new ClaimsIdentity();
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.Name);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.GivenName);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.FamilyName);
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.Email);
        AddClaim(jwtPayload, claimsIdentity, "email_verified");
        AddClaim(jwtPayload, claimsIdentity, "nonce");
        AddClaim(jwtPayload, claimsIdentity, "picture");
        return claimsIdentity;
    }
}