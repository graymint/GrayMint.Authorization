using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthentication
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly GrayMintExternalAuthentication _grayMintExternalAuthentication;

    public GrayMintAuthentication(
        IAuthorizationProvider authorizationProvider,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        GrayMintExternalAuthentication grayMintExternalAuthentication)
    {
        _authorizationProvider = authorizationProvider;
        _authenticationOptions = authenticationOptions.Value;
        _grayMintExternalAuthentication = grayMintExternalAuthentication;
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(CreateTokenParams createParams)
    {
        var tokenInfo = await CreateToken(createParams);
        return new AuthenticationHeaderValue(tokenInfo.Scheme, tokenInfo.Value);
    }

    public async Task<AccessToken> CreateToken(CreateTokenParams createParams)
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

        var tokenInfo = new AccessToken
        {
            Value = jwt,
            Scheme = JwtBearerDefaults.AuthenticationScheme,
            Expires = createParams.ExpirationTime
        };

        return tokenInfo;
    }

    private async Task<AccessToken> CreateIdToken(ClaimsIdentity claimsIdentity)
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

    public async Task<AccessToken> SignIn(ClaimsPrincipal claimsPrincipal, bool longExpiration)
    {
        // make sure email is verified for id token
        if (claimsPrincipal.FindFirstValue("token_use") == "id" && claimsPrincipal.FindFirstValue("email_verified") != "true")
            throw new AuthenticationException("Email has not been verified.");

        // get registered user id
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

    public async Task<AccessToken> CreateIdTokenFromGoogle(string idToken)
    {
        var claimsIdentity = await _grayMintExternalAuthentication.GetClaimsIdentityFromGoogle(idToken);
        var idTokenInfo = await CreateIdToken(claimsIdentity);
        return idTokenInfo;
    }

    public async Task<AccessToken> CreateIdTokenFromCognito(string idToken)
    {
        var claimsIdentity = await _grayMintExternalAuthentication.GetClaimsIdentityFromCognito(idToken);
        var idTokenInfo = await CreateIdToken(claimsIdentity);
        return idTokenInfo;
    }
}