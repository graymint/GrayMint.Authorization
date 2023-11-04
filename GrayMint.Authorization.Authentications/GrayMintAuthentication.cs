using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Claims;
using System.Web;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthentication
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly GrayMintIdTokenValidator _grayMintIdTokenValidator;

    public GrayMintAuthentication(
        IAuthorizationProvider authorizationProvider,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        GrayMintIdTokenValidator grayMintIdTokenValidator)
    {
        _authorizationProvider = authorizationProvider;
        _authenticationOptions = authenticationOptions.Value;
        _grayMintIdTokenValidator = grayMintIdTokenValidator;
    }

    internal static TokenValidationParameters GetTokenValidationParameters(GrayMintAuthenticationOptions options)
    {
        var securityKey = new SymmetricSecurityKey(options.Secret);
        var securityKeys = options.Secrets.Select(x => new SymmetricSecurityKey(x));
        var tokenValidation = new TokenValidationParameters
        {
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RequireSignedTokens = true,
            IssuerSigningKey = securityKey,
            IssuerSigningKeys = securityKeys,
            ValidIssuer = options.Issuer,
            ValidAudience = options.Audience ?? options.Issuer,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(TokenValidationParameters.DefaultClockSkew.TotalSeconds)
        };

        return tokenValidation;
    }

    private static void AddClaim(ClaimsIdentity source, ClaimsIdentity destination, string sourceType,
        string? destinationType = null, string? destinationValueType = null)
    {
        foreach (var claim in source.Claims.Where(x => x.Type == sourceType))
            destination.AddClaim(new Claim(destinationType ?? sourceType, claim.Value, destinationValueType ?? claim.ValueType));
    }

    public static ClaimsPrincipal CreateClaimsPrincipal(ClaimsIdentity claimsIdentity)
    {
        var destination = claimsIdentity.Clone();
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.Sub, ClaimTypes.NameIdentifier);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.Email, ClaimTypes.Email);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.GivenName, ClaimTypes.GivenName);
        AddClaim(claimsIdentity, destination, JwtRegisteredClaimNames.FamilyName, ClaimTypes.Surname);
        return new ClaimsPrincipal(destination);
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(CreateTokenParams createParams, DateTime? expirationTime = null)
    {
        expirationTime ??= DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout;
        var accessToken = await CreateToken(createParams, TokenUse.Access, expirationTime.Value);
        return new AuthenticationHeaderValue(accessToken.Scheme, accessToken.Value);
    }

    public async Task<ApiKey> CreateApiKey(CreateTokenParams createParams, DateTime? expirationTime = null)
    {
        ArgumentNullException.ThrowIfNull(createParams.Subject, nameof(createParams.Subject));

        expirationTime ??= DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout;
        var accessToken = await CreateToken(createParams, TokenUse.Access, expirationTime.Value);

        var ret = new ApiKey
        {
            AccessToken = accessToken,
            RefreshToken = null,
            UserId = createParams.Subject
        };
        return ret;
    }

    public async Task<ApiKey> CreateApiKeyWithRefreshToken(CreateTokenParams createParams,
        DateTime? refreshTokenExpirationTime = null)
    {
        ArgumentNullException.ThrowIfNull(createParams.Subject, nameof(createParams.Subject));

        var ret = new ApiKey
        {
            AccessToken = await CreateToken(createParams, TokenUse.Access, DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout),
            RefreshToken = await CreateToken(createParams, TokenUse.Refresh, refreshTokenExpirationTime ?? DateTime.UtcNow + _authenticationOptions.RefreshTokenShortTimeout),
            UserId = createParams.Subject
        };
        return ret;
    }

    public async Task<Token> CreateToken(CreateTokenParams createParams, string tokenUse, DateTime expirationTime)
    {
        var claimsIdentity = createParams.ClaimsIdentity?.Clone() ?? new ClaimsIdentity();

        // add subject
        if (createParams.Subject != null)
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, createParams.Subject));

        // add email
        if (createParams.Email != null)
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, createParams.Email));

        // try to add subject if not set
        if (claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub) == null)
        {
            var userId = await _authorizationProvider.GetUserId(CreateClaimsPrincipal(claimsIdentity));
            if (userId != null)
                claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userId));
        }

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
            authCode = await _authorizationProvider.GetAuthorizationCode(CreateClaimsPrincipal(claimsIdentity));
            if (string.IsNullOrEmpty(authCode))
                throw new Exception("Could not get the AuthorizationCode.");
        }

        // add authorization code to claim
        claimsIdentity.AddClaim(new Claim(GrayMintAuthenticationDefaults.AuthorizationCodeTypeName, authCode));
        claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.TokenUse, tokenUse));
        claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.Version, "2", ClaimValueTypes.Integer));

        // create jwt
        var audience = string.IsNullOrEmpty(_authenticationOptions.Audience) ? _authenticationOptions.Issuer : _authenticationOptions.Audience;
        var jwt = JwtUtil.CreateSymmetricJwt(
                key: _authenticationOptions.Secret,
                issuer: _authenticationOptions.Issuer,
                audience: audience,
                claims: claimsIdentity.Claims.ToArray(),
                expirationTime: expirationTime);

        var token = new Token
        {
            Value = jwt,
            Scheme = JwtBearerDefaults.AuthenticationScheme,
            ExpirationTime = expirationTime,
            IssuedTime = DateTime.UtcNow,
            ClaimsPrincipal = CreateClaimsPrincipal(claimsIdentity)
        };

        return token;
    }

    public Task<ApiKey> RefreshToken(string refreshToken)
    {
        // validate token
        var claimsPrincipal = _grayMintIdTokenValidator.ValidateGrayMintToken(refreshToken);
        //var userId = await _authorizationProvider.GetUserId(claimsPrincipal) ?? throw new UnregisteredUser();

        //// find expiration
        //var maxExpiration = DateTime.UtcNow + _authenticationOptions.RefreshTokenShortTimeout;
        //var expirationTime = DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout;
        //if (expirationTime > maxExpiration || longExpiration)
        //    expirationTime = maxExpiration;

        //// find auth_time. it can not be older than UserTokenLongExpiration
        //var authTimeClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.AuthTime);
        //var authTime = authTimeClaim?.Value != null
        //    ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(authTimeClaim.Value)).UtcDateTime
        //    : DateTime.UtcNow;

        //if (authTime < DateTime.UtcNow - _authenticationOptions.RefreshTokenLongTimeout)
        //    throw new AuthenticationException();

        //var accessToken = await CreateToken(new CreateTokenParams
        //{
        //    Subject = userId,
        //    AuthTime = authTime
        //}, TokenUse.Access, expirationTime);

        //return accessToken;
        throw new NotImplementedException();
    }

    public async Task<ApiKey> SignIn(string idToken, bool longExpiration)
    {
        var claimsIdentity = await _grayMintIdTokenValidator.ValidateIdToken(idToken);

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
            throw new AuthenticationException("This is not an id token.");

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.EmailVerified, "true"))
            throw new AuthenticationException("Email has not been verified.");

        // check user existence
        var userId = await _authorizationProvider.GetUserId(CreateClaimsPrincipal(claimsIdentity))
            ?? throw new UnregisteredUser();

        var refreshTokenExpirationTime = longExpiration
            ? DateTime.UtcNow + _authenticationOptions.RefreshTokenLongTimeout
            : DateTime.UtcNow + _authenticationOptions.RefreshTokenShortTimeout;

        var apiKey = await CreateApiKeyWithRefreshToken(new CreateTokenParams
        {
            Subject = userId,
            ClaimsIdentity = claimsIdentity,
        }, refreshTokenExpirationTime);

        return apiKey;
    }

    public async Task<Token> CreateIdToken(ClaimsIdentity claimsIdentity)
    {
        var expirationTime = DateTime.UtcNow + _authenticationOptions.IdTokenExpiration;
        var token = await CreateToken(new CreateTokenParams
        {
            AuthCode = AuthorizationConstants.AnyAuthCode,
            ClaimsIdentity = claimsIdentity
        }, TokenUse.Id, expirationTime);

        return token;
    }

    public async Task<Uri> GetSignInRedirectUrl(string idToken, string? csrfToken)
    {
        if (_authenticationOptions.SignInRedirectUrl == null)
            throw new InvalidOperationException("TeamController:SignInRedirectUrl has not been configured in app settings.");

        var claimsIdentity = await _grayMintIdTokenValidator.ValidateIdToken(idToken);
        var token = await CreateIdToken(claimsIdentity);

        // Adding a parameter
        var uriBuilder = new UriBuilder(_authenticationOptions.SignInRedirectUrl);
        var query = HttpUtility.ParseQueryString(uriBuilder.Query);
        query["id_token"] = token.Value;
        query["csrf_token"] = csrfToken;
        uriBuilder.Query = query.ToString();
        return uriBuilder.Uri;
    }

    public Uri GetGoogleSignInUrl(string csrfToken, string? nonce, string redirectUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(_authenticationOptions.GoogleClientId);

        const string baseUrl = "https://accounts.google.com/gsi/select";
        var query = new Dictionary<string, string?>
        {
            { "client_id", _authenticationOptions.GoogleClientId },
            { "ux_mode", "redirect" },
            { "login_uri", redirectUrl },
            { "ui_mode", "card" },
            { "g_csrf_token", csrfToken }
        };

        if (nonce != null)
            query.Add("nonce", nonce);

        var uriBuilder = new UriBuilder(baseUrl);
        var queryToAppend = QueryHelpers.AddQueryString(uriBuilder.Query, query);
        uriBuilder.Query = queryToAppend;
        return uriBuilder.Uri;
    }
}