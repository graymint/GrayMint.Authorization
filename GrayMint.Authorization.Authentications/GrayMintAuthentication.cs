﻿using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Security.Claims;
using System.Web;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Authentications.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace GrayMint.Authorization.Authentications;

public class GrayMintAuthentication
{
    private readonly IAuthorizationProvider _authorizationProvider;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly GrayMintTokenValidator _grayMintIdTokenValidator;

    public GrayMintAuthentication(
        IAuthorizationProvider authorizationProvider,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions,
        GrayMintTokenValidator grayMintIdTokenValidator)
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

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(
        TokenOptions options, ClaimsIdentity? claimsIdentity = null, DateTime? expirationTime = null)
    {
        expirationTime ??= DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout;
        var accessToken = await CreateToken(options, claimsIdentity, TokenUse.Access, expirationTime.Value);
        return new AuthenticationHeaderValue(accessToken.Scheme, accessToken.Value);
    }

    private DateTime GetRefreshTokenExpirationTime(RefreshTokenType refreshTokenType, DateTime? explicitTime = null)
    {
        if (explicitTime != null)
            return explicitTime.Value;

        return refreshTokenType switch
        {
            RefreshTokenType.Web => DateTime.UtcNow + _authenticationOptions.RefreshTokenWebTimeout,
            RefreshTokenType.App => DateTime.UtcNow + _authenticationOptions.RefreshTokenAppTimeout,
            _ => throw new AuthenticationException("Invalid refresh_token_type.")
        };
    }

    public async Task<ApiKey> CreateApiKey(ApiKeyOptions options)
    {
        // create access token
        var accessToken = await CreateToken(
            options.TokenOptions,
            options.ClaimsIdentity,
            TokenUse.Access,
            options.AccessTokenExpirationTime ?? DateTime.UtcNow + _authenticationOptions.AccessTokenTimeout);

        // create refresh token
        Token? refreshToken = null;
        if (options.RefreshTokenType != RefreshTokenType.None && _authenticationOptions.AllowRefreshToken)
        {
            // add refresh token clams
            var clientIdentity = options.ClaimsIdentity.Clone();
            ClaimUtil.SetClaim(clientIdentity, new Claim(GrayMintClaimTypes.RefreshTokenType, options.RefreshTokenType.ToString()));
            ClaimUtil.SetClaim(clientIdentity, new Claim(GrayMintClaimTypes.AccessToken, accessToken.Value));
            if (options.RefreshTokenMaxExpirationTime != null)
                ClaimUtil.SetClaim(clientIdentity, ClaimUtil.CreateClaimTime(GrayMintClaimTypes.AuthEndTime, options.RefreshTokenMaxExpirationTime.Value));

            refreshToken = await CreateToken(
                options.TokenOptions,
                clientIdentity: clientIdentity,
                tokenUse: TokenUse.Refresh,
                expTime: GetRefreshTokenExpirationTime(options.RefreshTokenType, options.RefreshTokenExpirationTime));
        }

        // create apiKey
        var ret = new ApiKey
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            UserId = accessToken.ClaimsPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty
        };
        return ret;
    }


    public async Task<Token> CreateToken(TokenOptions tokenOptions, ClaimsIdentity? clientIdentity, string tokenUse, DateTime expTime)
    {
        var claimsIdentity = clientIdentity?.Clone() ?? new ClaimsIdentity();

        // try to add subject if not set
        if (claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub) == null)
        {
            var userId = await _authorizationProvider.GetUserId(ClaimUtil.CreateClaimsPrincipal(claimsIdentity));
            if (userId != null)
                ClaimUtil.SetClaim(claimsIdentity, new Claim(JwtRegisteredClaimNames.Sub, userId));
        }

        // AuthCode. try to retrieve it from authorization Provider if not set
        if (claimsIdentity.FindFirst(x => x.Type == GrayMintClaimTypes.AuthCode) == null)
        {
            var authCode = await _authorizationProvider.GetAuthorizationCode(ClaimUtil.CreateClaimsPrincipal(claimsIdentity));
            if (!string.IsNullOrEmpty(authCode))
                ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.AuthCode, authCode));
        }

        // validate times
        var authTime = ClaimUtil.GetUtcTime(claimsIdentity, JwtRegisteredClaimNames.AuthTime);
        var authEndTime = ClaimUtil.GetUtcTime(claimsIdentity, GrayMintClaimTypes.AuthEndTime);
        if (authTime == null && authEndTime != null) throw new InvalidOperationException("AuthEndTime can not be set when authTime is null.");
        if (authTime > expTime) throw new InvalidOperationException("AuthTime can not be more than ExpTime.");
        if (authTime > authEndTime) throw new InvalidOperationException("AuthTime can not be more than AuthEndTime.");
        if (expTime > authEndTime) throw new InvalidOperationException("ExpTime can not be more than AuthEndTime.");

        // add authorization code to claim
        ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.TokenUse, tokenUse));
        ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.Version, "2", ClaimValueTypes.Integer));

        // create jwt
        var audience = string.IsNullOrEmpty(_authenticationOptions.Audience) ? _authenticationOptions.Issuer : _authenticationOptions.Audience;

        var jwt = JwtUtil.CreateSymmetricJwt(
                key: _authenticationOptions.Secret,
                issuer: _authenticationOptions.Issuer,
                audience: audience,
                claims: claimsIdentity.Claims.ToArray(),
                expirationTime: expTime);

        var token = new Token
        {
            Value = jwt,
            Scheme = JwtBearerDefaults.AuthenticationScheme,
            ExpirationTime = expTime,
            IssuedTime = DateTime.UtcNow,
            ClaimsPrincipal = ClaimUtil.CreateClaimsPrincipal(claimsIdentity)
        };

        // ValidateAuthCode
        if (tokenOptions.ValidateAuthCode)
        {
            var authCode = claimsIdentity.FindFirst(x => x.Type == GrayMintClaimTypes.AuthCode)?.Value;
            if (string.IsNullOrEmpty(authCode) || await _authorizationProvider.GetAuthorizationCode(token.ClaimsPrincipal) != authCode)
                throw new AuthenticationException("Could not validate AuthorizationCode.");
        }

        // ValidateSubject
        if (tokenOptions.ValidateSubject)
        {
            var subject = claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(subject) || await _authorizationProvider.GetUserId(token.ClaimsPrincipal) != subject)
                throw new AuthenticationException("Could not validate UserId.");
        }

        return token;
    }

    public async Task<ApiKey> RefreshToken(string refreshToken)
    {
        // validate token
        var claimsIdentity = await _grayMintIdTokenValidator.ValidateGrayMintToken(refreshToken);
        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Refresh))
            throw new AuthenticationException("This is not a refresh token.");

        // find refresh token type
        var refreshTokenType = Enum.Parse<RefreshTokenType>(ClaimUtil.GetRequiredClaimString(claimsIdentity, GrayMintClaimTypes.RefreshTokenType), true);
        var issuedTime = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Iat);
        var expTime = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Exp);
        var authTime = ClaimUtil.GetUtcTime(claimsIdentity, JwtRegisteredClaimNames.AuthTime);

        // set authEndTime if not exists
        var authEndTime = ClaimUtil.GetUtcTime(claimsIdentity, GrayMintClaimTypes.AuthEndTime)
            ?? refreshTokenType switch
            {
                RefreshTokenType.App => authTime + _authenticationOptions.SessionAppTimeout,
                _ => authTime + _authenticationOptions.SessionWebTimeout
            };

        if (DateTime.UtcNow > authEndTime)
            throw new AuthenticationException("Can not use this refresh token anymore.");

        // Calculate refresh token expiration tome
        var newExpTime = DateTime.UtcNow + (expTime - issuedTime);
        if (newExpTime > authEndTime)
            newExpTime = authEndTime.Value;

        // extract old access token claimIdentity
        var oldAccessToken = claimsIdentity.FindFirst(GrayMintClaimTypes.AccessToken)?.Value
            ?? throw new AuthenticationException("Could not extract access toke from refresh token.");
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.ReadJwtToken(oldAccessToken);
        var accessTokenClaimIdentity = new ClaimsIdentity(token.Claims);

        // Create the refresh token  with new access key
        var apiKey = await CreateApiKey(
            new ApiKeyOptions
            {
                TokenOptions = new TokenOptions { ValidateAuthCode = false, ValidateSubject = false },
                ClaimsIdentity = accessTokenClaimIdentity,
                RefreshTokenType = refreshTokenType,
                RefreshTokenExpirationTime = newExpTime
            });

        return apiKey;
    }

    public async Task<ApiKey> SignIn(string idToken, RefreshTokenType refreshTokenType)
    {
        var claimsIdentity = await _grayMintIdTokenValidator.ValidateIdToken(idToken);

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
            throw new AuthenticationException("This is not an id token.");

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.EmailVerified, "true"))
            throw new AuthenticationException("Email has not been verified.");

        // check user existence
        var userId = await _authorizationProvider.GetUserId(ClaimUtil.CreateClaimsPrincipal(claimsIdentity))
            ?? throw new UnregisteredUser();

        // update userId in claims
        var issuedAt = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Iat);
        ClaimUtil.SetClaim(claimsIdentity, new Claim(JwtRegisteredClaimNames.Sub, userId));
        ClaimUtil.SetClaim(claimsIdentity, ClaimUtil.CreateClaimTime(JwtRegisteredClaimNames.AuthTime, issuedAt));

        var apiKey = await CreateApiKey(new ApiKeyOptions
        {
            TokenOptions = new TokenOptions
            {
                ValidateAuthCode = true,
                ValidateSubject = true,
            },
            ClaimsIdentity = claimsIdentity,
            RefreshTokenType = refreshTokenType
        });

        return apiKey;
    }

    public async Task<Token> CreateIdToken(TokenOptions tokenOptions, ClaimsIdentity? claimsIdentity = null)
    {
        var expirationTime = DateTime.UtcNow + _authenticationOptions.IdTokenTimeout;
        var token = await CreateToken(tokenOptions, claimsIdentity, TokenUse.Id, expirationTime);
        return token;
    }

    public async Task<Uri> GetSignInRedirectUrl(string idToken, string? csrfToken)
    {
        if (_authenticationOptions.SignInRedirectUrl == null)
            throw new InvalidOperationException("TeamController:SignInRedirectUrl has not been configured in app settings.");

        var claimsIdentity = await _grayMintIdTokenValidator.ValidateIdToken(idToken);
        var token = await CreateIdToken(new TokenOptions { ValidateAuthCode = false, ValidateSubject = false }, claimsIdentity);

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

