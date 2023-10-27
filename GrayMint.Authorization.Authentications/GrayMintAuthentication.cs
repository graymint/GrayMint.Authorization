using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Authentication;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications.CognitoAuthentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthentication
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly CognitoAuthenticationOptions _cognitoOptions;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _memoryCache;

    public GrayMintAuthentication(
        IAuthorizationProvider authorizationProvider,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        IOptions<CognitoAuthenticationOptions> cognitoOptions,
        HttpClient httpClient,
        IMemoryCache memoryCache)
    {
        _authorizationProvider = authorizationProvider;
        _cognitoOptions = cognitoOptions.Value;
        _authenticationOptions = authenticationOptions.Value;
        _httpClient = httpClient;
        _memoryCache = memoryCache;
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(CreateTokenParams createParams)
    {
        var tokenInfo = await CreateToken(createParams);
        return new AuthenticationHeaderValue(tokenInfo.AuthenticationScheme, tokenInfo.Token);
    }

    public async Task<TokenInfo> CreateToken(CreateTokenParams createParams)
    {
        var claimsIdentity = createParams.ClaimsIdentity?.Clone() ?? new ClaimsIdentity();

        // add subject
        if (createParams.Subject != null)
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, createParams.Subject));

        // try to add subject if not set
        if (claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub) == null)
        {
            var userId = await _authorizationProvider.GetUserId(new ClaimsPrincipal(claimsIdentity));
            if (userId != null)
                claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userId));
        }

        // add email
        if (createParams.Email != null)
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, createParams.Email));

        // add AuthTime
        if (createParams.AuthTime != null)
        {
            var unixTime = ((DateTimeOffset)createParams.AuthTime).ToUnixTimeSeconds();
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.AuthTime, unixTime.ToString(), ClaimValueTypes.Integer64));
        }

        // get authcode by transforming jwt claim to .net claim
        var authCode = createParams.AuthCode;
        if (authCode == null)
        {
            var tempIdentity = claimsIdentity.Clone();
            var nameClaim = tempIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub);
            if (nameClaim != null) tempIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, nameClaim.Value));

            var emailClaim = tempIdentity.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email);
            if (emailClaim != null) tempIdentity.AddClaim(new Claim(ClaimTypes.Email, emailClaim.Value));

            authCode = await _authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(tempIdentity));
            if (string.IsNullOrEmpty(authCode))
                throw new Exception("Could not get the AuthorizationCode.");
        }

        // add authorization code to claim
        claimsIdentity.AddClaim(new Claim(GrayMintAuthenticationDefaults.AuthorizationCodeTypeName, authCode));
        claimsIdentity.AddClaim(new Claim("token_use", createParams.TokenUse));

        // create jwt
        var audience = string.IsNullOrEmpty(_authenticationOptions.Audience) ? _authenticationOptions.Issuer : _authenticationOptions.Audience;
        var jwt = JwtUtil.CreateSymmetricJwt(
                key: _authenticationOptions.Secret,
                issuer: _authenticationOptions.Issuer,
                audience: audience,
                claims: claimsIdentity.Claims.ToArray(),
                expirationTime: createParams.ExpirationTime);

        var tokenInfo = new TokenInfo
        {
            Token = jwt,
            AuthenticationScheme = JwtBearerDefaults.AuthenticationScheme,
            ExpirationTime = createParams.ExpirationTime
        };

        return tokenInfo;
    }

    private async Task<TokenInfo> CreateIdToken(ClaimsIdentity claimsIdentity)
    {
        var expirationTime = DateTime.UtcNow + _authenticationOptions.IdTokenExpiration;
        var token = await CreateToken(new CreateTokenParams
        {
            AuthCode = AuthorizationConstants.AnyAuthCode,
            TokenUse = "id",
            ExpirationTime = expirationTime,
            ClaimsIdentity = claimsIdentity
        });

        return token;
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

    public async Task<TokenInfo> CreateIdTokenFromCognito(string idToken)
    {
        var cognitoArn = new AwsArn(_cognitoOptions.CognitoArn);
        var metadataAddress = $"https://{cognitoArn.Service}.{cognitoArn.Region}.amazonaws.com/{cognitoArn.ResourceId}/.well-known/openid-configuration";
        var openIdConfig = await GetOpenIdConnectConfiguration(metadataAddress);

        // Set the parameters for token validation
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, 
            ValidIssuer = openIdConfig.Issuer,
            ValidateAudience = true, 
            ValidAudience = _cognitoOptions.CognitoClientId, // Replace with your API identifier
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
        AddClaim(jwtPayload, claimsIdentity, JwtRegisteredClaimNames.Email);
        AddClaim(jwtPayload, claimsIdentity, "email_verified");
        AddClaim(jwtPayload, claimsIdentity, "nonce");
        AddClaim(jwtPayload, claimsIdentity, "picture");
        AddClaim(jwtPayload, claimsIdentity, "cognito:groups");
        var ret = await CreateIdToken(claimsIdentity);
        return ret;
    }

    public async Task<TokenInfo> CreateIdTokenFromGoogle(string idToken)
    {
        // check credential using google endpoint
        var jwtPayload = await _httpClient.GetFromJsonAsync<JwtPayload>("https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken)
                        ?? throw new AuthenticationException("Invalid credential.");

        // convert claims
        var claimsIdentity = new ClaimsIdentity();
        if (jwtPayload.TryGetValue(JwtRegisteredClaimNames.Name, out var nameValue)) claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Name, nameValue.ToString()!, ClaimValueTypes.String));
        if (jwtPayload.TryGetValue(JwtRegisteredClaimNames.GivenName, out var givenNameValue)) claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.GivenName, givenNameValue.ToString()!, ClaimValueTypes.String));
        if (jwtPayload.TryGetValue(JwtRegisteredClaimNames.FamilyName, out var familyValue)) claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.FamilyName, familyValue.ToString()!, ClaimValueTypes.String));
        if (jwtPayload.TryGetValue(JwtRegisteredClaimNames.Email, out var emailValue)) claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, emailValue.ToString()!, ClaimValueTypes.String));
        if (jwtPayload.TryGetValue("email_verified", out var emailVerifiedValue)) claimsIdentity.AddClaim(new Claim("email_verified", emailVerifiedValue.ToString()!, ClaimValueTypes.Boolean));
        if (jwtPayload.TryGetValue("nonce", out var nonceValue)) claimsIdentity.AddClaim(new Claim("nonce", nonceValue.ToString()!, ClaimValueTypes.String));
        if (jwtPayload.TryGetValue("picture", out var pictureValue)) claimsIdentity.AddClaim(new Claim("picture", pictureValue.ToString()!, ClaimValueTypes.String));

        // check claims
        if (emailVerifiedValue?.ToString() != "true") throw new AuthenticationException("Email is not verified.");
        if (!jwtPayload.TryGetValue(JwtRegisteredClaimNames.Aud, out var aud) || aud.ToString() != _authenticationOptions.GoogleClientId)
            throw new AuthenticationException("Invalid audience. The token is not issued for this service.");

        var ret = await CreateIdToken(claimsIdentity);
        return ret;
    }

    public async Task<TokenInfo> SignIn(ClaimsPrincipal claimsPrincipal, bool longExpiration)
    {
        var userId = await _authorizationProvider.GetUserId(claimsPrincipal) ?? throw new UnregisteredUser();

        // find expiration
        var maxExpiration = DateTime.UtcNow + _authenticationOptions.AccessTokenLongExpiration;
        var expirationTime = DateTime.UtcNow + _authenticationOptions.AccessTokenShortExpiration;
        if (expirationTime > maxExpiration || longExpiration)
            expirationTime = maxExpiration;

        // find auth_time. it can not be older than UserTokenLongExpiration
        var authTimeClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.AuthTime);
        var authTime = authTimeClaim?.Value != null
            ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(authTimeClaim.Value)).UtcDateTime
            : DateTime.UtcNow;

        if (authTime < DateTime.UtcNow - _authenticationOptions.AccessTokenLongExpiration)
            throw new AuthenticationException();

        var tokenInfo = await CreateToken(new CreateTokenParams
        {
            Subject = userId,
            ExpirationTime = expirationTime,
            AuthTime = authTime
        });

        return tokenInfo;
    }
}