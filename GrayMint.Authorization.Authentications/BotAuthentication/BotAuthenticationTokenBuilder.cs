using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Authentication;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications.BotAuthentication;

public class BotAuthenticationTokenBuilder
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly BotAuthenticationOptions _botAuthenticationOptions;
    private readonly HttpClient _httpClient;

    public BotAuthenticationTokenBuilder(IAuthorizationProvider authorizationProvider, IOptions<BotAuthenticationOptions> botAuthenticationOptions, HttpClient httpClient)
    {
        _authorizationProvider = authorizationProvider;
        _httpClient = httpClient;
        _botAuthenticationOptions = botAuthenticationOptions.Value;
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(CreateTokenParams createParams)
    {
        var tokenInfo = await CreateToken(createParams);
        return new AuthenticationHeaderValue(tokenInfo.AuthenticationScheme, tokenInfo.Token);
    }

    public async Task<BotTokenInfo> CreateToken(CreateTokenParams createParams)
    {
        var claimsIdentity = createParams.ClaimsIdentity ?? new ClaimsIdentity();

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
        claimsIdentity.AddClaim(new Claim(BotAuthenticationDefaults.AuthorizationCodeTypeName, authCode));
        claimsIdentity.AddClaim(new Claim("token_use", createParams.TokenUse));

        // create jwt
        var audience = string.IsNullOrEmpty(_botAuthenticationOptions.BotAudience) ? _botAuthenticationOptions.BotIssuer : _botAuthenticationOptions.BotAudience;
        var jwt = JwtUtil.CreateSymmetricJwt(
                key: _botAuthenticationOptions.BotKey,
                issuer: _botAuthenticationOptions.BotIssuer,
                audience: audience,
                claims: claimsIdentity.Claims.ToArray(),
                expirationTime: createParams.ExpirationTime);

        var tokenInfo = new BotTokenInfo
        {
            Token = jwt,
            AuthenticationScheme = JwtBearerDefaults.AuthenticationScheme,
            ExpirationTime = createParams.ExpirationTime
        };

        return tokenInfo;
    }

    private async Task<BotTokenInfo> CreateIdToken(ClaimsIdentity claimsIdentity)
    {
        var expirationTime = DateTime.UtcNow + _botAuthenticationOptions.IdTokenExpiration;
        var token = await CreateToken(new CreateTokenParams
        {
            AuthCode = AuthorizationConstants.AnyAuthCode,
            TokenUse = "id",
            ExpirationTime = expirationTime,
            ClaimsIdentity = claimsIdentity
        });

        return token;
    }

    public async Task<BotTokenInfo> CreateIdTokenFromGoogle(string idToken)
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
        if (!jwtPayload.TryGetValue(JwtRegisteredClaimNames.Aud, out var aud) || aud.ToString() != _botAuthenticationOptions.GoogleClientId)
            throw new AuthenticationException("Invalid audience. The token is not issued for this service.");

        var ret = await CreateIdToken(claimsIdentity);
        return ret;
    }

    public async Task<BotTokenInfo> SignIn(ClaimsPrincipal claimsPrincipal, bool longExpiration)
    {
        var userId = await _authorizationProvider.GetUserId(claimsPrincipal) ?? throw new UnregisteredUser();

        // find expiration
        var maxExpiration = DateTime.UtcNow + _botAuthenticationOptions.AccessTokenLongExpiration;
        var expirationTime = DateTime.UtcNow + _botAuthenticationOptions.AccessTokenShortExpiration;
        if (expirationTime > maxExpiration || longExpiration)
            expirationTime = maxExpiration;

        // find auth_time. it can not be older than UserTokenLongExpiration
        var authTimeClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.AuthTime);
        var authTime = authTimeClaim?.Value != null
            ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(authTimeClaim.Value)).UtcDateTime
            : DateTime.UtcNow;

        if (authTime < DateTime.UtcNow - _botAuthenticationOptions.AccessTokenLongExpiration)
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