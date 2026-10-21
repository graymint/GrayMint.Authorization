using System.IdentityModel.Tokens.Jwt;
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

public class GrayMintAuthentication(
    IAuthorizationProvider authorizationProvider,
    IOptions<GrayMintAuthenticationOptions> authenticationOptions,
    GrayMintTokenValidator grayMintIdTokenValidator)
{
    private readonly GrayMintAuthenticationOptions _authenticationOptions = authenticationOptions.Value;

    // as an identity provider writes them and as a validated token maps them
    private static readonly HashSet<string> SignInProfileClaimTypes = [
        JwtRegisteredClaimNames.Email, ClaimTypes.Email,
        JwtRegisteredClaimNames.Name, ClaimTypes.Name,
        JwtRegisteredClaimNames.GivenName, ClaimTypes.GivenName,
        JwtRegisteredClaimNames.FamilyName, ClaimTypes.Surname,
        JwtRegisteredClaimNames.PhoneNumber, ClaimTypes.MobilePhone,
        GrayMintClaimTypes.Picture, GrayMintClaimTypes.EmailVerified
    ];

    internal static TokenValidationParameters GetTokenValidationParameters(GrayMintAuthenticationOptions options)
    {
        var securityKey = new SymmetricSecurityKey(options.Secret);
        var securityKeys = options.Secrets.Select(x => new SymmetricSecurityKey(x));
        var tokenValidation = new TokenValidationParameters {
            NameClaimType = JwtRegisteredClaimNames.Sub,
            RequireSignedTokens = true,
            IssuerSigningKey = securityKey,
            IssuerSigningKeys = securityKeys,
            ValidIssuer = options.Issuer,
            ValidAudience = options.Audience ?? options.Issuer,
            ValidAudiences = options.Audiences,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateLifetime = true,
            ClockSkew = TokenValidationParameters.DefaultClockSkew
        };

        return tokenValidation;
    }

    public async Task<AuthenticationHeaderValue> CreateAuthenticationHeader(
        ClaimsIdentity claimsIdentity, ValidateOptions? validateOptions = null, DateTime? expirationTime = null)
    {
        expirationTime ??= JwtUtil.UtcNow + _authenticationOptions.AccessTokenTimeout;
        var accessToken = await CreateToken(claimsIdentity, validateOptions, TokenUse.Access, expirationTime.Value);
        return new AuthenticationHeaderValue(accessToken.Scheme, accessToken.Value);
    }

    private DateTime GetRefreshTokenExpirationTime(RefreshTokenType refreshTokenType, DateTime? explicitTime = null)
    {
        if (explicitTime != null)
            return explicitTime.Value;

        return refreshTokenType switch {
            RefreshTokenType.Web => JwtUtil.UtcNow + _authenticationOptions.RefreshTokenWebTimeout,
            RefreshTokenType.App => JwtUtil.UtcNow + _authenticationOptions.RefreshTokenAppTimeout,
            _ => throw new AuthenticationException("Invalid refresh_token_type.")
        };
    }

    public async Task<ApiKey> CreateApiKey(ClaimsIdentity claimsIdentity, ApiKeyOptions? options = null)
    {
        options ??= new ApiKeyOptions();

        // create access token; an explicit session end caps it, as it does the refresh token
        var accessTokenExpirationTime =
            options.AccessTokenExpirationTime ?? JwtUtil.UtcNow + _authenticationOptions.AccessTokenTimeout;
        if (options.RefreshTokenMaxExpirationTime < accessTokenExpirationTime)
            accessTokenExpirationTime = options.RefreshTokenMaxExpirationTime.Value;

        var accessToken = await CreateToken(
            claimsIdentity,
            options.ValidateOptions,
            TokenUse.Access,
            accessTokenExpirationTime);

        // create refresh token
        Token? refreshToken = null;
        if (options.RefreshTokenType != RefreshTokenType.None) {
            if (!_authenticationOptions.AllowRefreshToken)
                throw new UnauthorizedAccessException("Refresh token is not available on the server.");

            // a session ends counting from its sign-in, so a refresh token without one would refresh forever
            if (ClaimUtil.GetUtcTime(claimsIdentity, JwtRegisteredClaimNames.AuthTime) == null)
                throw new InvalidOperationException(
                    $"A refresh token needs the sign-in time ({JwtRegisteredClaimNames.AuthTime}).");

            // add refresh token clams
            claimsIdentity = claimsIdentity.Clone();
            ClaimUtil.SetClaim(claimsIdentity,
                new Claim(GrayMintClaimTypes.RefreshTokenType, options.RefreshTokenType.ToString()));
            ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.AccessToken, accessToken.Value));
            if (options.RefreshTokenMaxExpirationTime != null)
                ClaimUtil.SetClaim(claimsIdentity,
                    ClaimUtil.CreateClaimTime(GrayMintClaimTypes.AuthEndTime,
                        options.RefreshTokenMaxExpirationTime.Value));

            var refreshTokenExpirationTime =
                GetRefreshTokenExpirationTime(options.RefreshTokenType, options.RefreshTokenExpirationTime);
            if (options.RefreshTokenMaxExpirationTime < refreshTokenExpirationTime)
                refreshTokenExpirationTime = options.RefreshTokenMaxExpirationTime.Value;

            refreshToken = await CreateToken(
                claimsIdentity: claimsIdentity,
                options.ValidateOptions,
                tokenUse: TokenUse.Refresh,
                expTime: refreshTokenExpirationTime);
        }

        // create apiKey
        var ret = new ApiKey {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            UserId = accessToken.ClaimsPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty
        };
        return ret;
    }


    public async Task<Token> CreateToken(ClaimsIdentity claimsIdentity, ValidateOptions? tokenOptions, string tokenUse,
        DateTime expTime)
    {
        claimsIdentity = claimsIdentity.Clone();
        tokenOptions ??= new ValidateOptions();

        // try to add subject if not set
        if (claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub) == null) {
            var userId = await authorizationProvider.GetUserId(ClaimUtil.CreateClaimsPrincipal(claimsIdentity));
            if (userId != null)
                ClaimUtil.SetClaim(claimsIdentity, new Claim(JwtRegisteredClaimNames.Sub, userId));
        }

        // AuthCode. try to retrieve it from authorization Provider if not set
        if (claimsIdentity.FindFirst(x => x.Type == GrayMintClaimTypes.AuthCode) == null) {
            var authCode =
                await authorizationProvider.GetAuthorizationCode(ClaimUtil.CreateClaimsPrincipal(claimsIdentity));
            if (!string.IsNullOrEmpty(authCode))
                ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.AuthCode, authCode));
        }

        // validate times
        var authTime = ClaimUtil.GetUtcTime(claimsIdentity, JwtRegisteredClaimNames.AuthTime);
        var authEndTime = ClaimUtil.GetUtcTime(claimsIdentity, GrayMintClaimTypes.AuthEndTime);
        if (authTime == null && authEndTime != null)
            throw new InvalidOperationException("AuthEndTime can not be set when authTime is null.");
        if (authTime > expTime) throw new InvalidOperationException("AuthTime can not be more than ExpTime.");
        if (authTime > authEndTime) throw new InvalidOperationException("AuthTime can not be more than AuthEndTime.");
        if (expTime > authEndTime) throw new InvalidOperationException("ExpTime can not be more than AuthEndTime.");

        // add authorization code to claim
        ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.TokenUse, tokenUse));
        ClaimUtil.SetClaim(claimsIdentity, new Claim(GrayMintClaimTypes.Version, "2", ClaimValueTypes.Integer));

        // create jwt
        var audience = string.IsNullOrEmpty(_authenticationOptions.Audience)
            ? _authenticationOptions.Issuer
            : _authenticationOptions.Audience;

        var jwt = JwtUtil.CreateSymmetricJwt(
            key: _authenticationOptions.Secret,
            issuer: _authenticationOptions.Issuer,
            audience: audience,
            claims: [.. claimsIdentity.Claims],
            expirationTime: expTime);

        var token = new Token {
            Value = jwt,
            Scheme = JwtBearerDefaults.AuthenticationScheme,
            ExpirationTime = expTime,
            IssuedTime = JwtUtil.UtcNow,
            ClaimsPrincipal = ClaimUtil.CreateClaimsPrincipal(claimsIdentity)
        };

        // ValidateAuthCode
        if (tokenOptions.ValidateAuthCode) {
            var authCode = claimsIdentity.FindFirst(x => x.Type == GrayMintClaimTypes.AuthCode)?.Value;
            if (string.IsNullOrEmpty(authCode) ||
                await authorizationProvider.GetAuthorizationCode(token.ClaimsPrincipal) != authCode)
                throw new AuthenticationException("Could not validate AuthorizationCode.");
        }

        // ValidateSubject
        if (tokenOptions.ValidateSubject) {
            var subject = claimsIdentity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrEmpty(subject) ||
                await authorizationProvider.GetUserId(token.ClaimsPrincipal) != subject)
                throw new AuthenticationException("Could not validate UserId.");
        }

        return token;
    }

    // a used refresh token stays valid until it expires: rotating them would cost a database write per refresh,
    // and resetting the user's authorization code ends them all
    public async Task<ApiKey> RefreshToken(string refreshToken)
    {
        // validate token
        var claimsIdentity = await grayMintIdTokenValidator.ValidateGrayMintToken(refreshToken);
        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Refresh))
            throw new AuthenticationException("This is not a refresh token.");

        // find refresh token type
        var refreshTokenType =
            Enum.Parse<RefreshTokenType>(
                ClaimUtil.GetRequiredClaimString(claimsIdentity, GrayMintClaimTypes.RefreshTokenType), true);
        var issuedTime = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Iat);
        var expTime = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Exp);
        var authTime = ClaimUtil.GetUtcTime(claimsIdentity, JwtRegisteredClaimNames.AuthTime);

        // set authEndTime if not exists; a token with neither has no end, so it refreshes nothing
        var authEndTime = ClaimUtil.GetUtcTime(claimsIdentity, GrayMintClaimTypes.AuthEndTime)
                          ?? refreshTokenType switch {
                              RefreshTokenType.App => authTime + _authenticationOptions.SessionAppTimeout,
                              _ => authTime + _authenticationOptions.SessionWebTimeout
                          }
                          ?? throw new AuthenticationException("This refresh token has no session end.");

        if (JwtUtil.UtcNow > authEndTime)
            throw new AuthenticationException("Can not use this refresh token anymore.");

        // Calculate refresh token expiration tome
        var newExpTime = JwtUtil.UtcNow + (expTime - issuedTime);
        if (newExpTime > authEndTime)
            newExpTime = authEndTime;

        // extract old access token claimIdentity
        var oldAccessToken = claimsIdentity.FindFirst(GrayMintClaimTypes.AccessToken)?.Value
                             ?? throw new AuthenticationException("Could not extract access toke from refresh token.");
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.ReadJwtToken(oldAccessToken);
        var accessTokenClaimIdentity = new ClaimsIdentity(token.Claims);

        // Create the refresh token  with new access key; the session's end rides along and caps both, so it holds
        // however often the pair is renewed
        var apiKey = await CreateApiKey(
            accessTokenClaimIdentity,
            new ApiKeyOptions {
                RefreshTokenType = refreshTokenType,
                RefreshTokenExpirationTime = newExpTime,
                RefreshTokenMaxExpirationTime = authEndTime
            });

        return apiKey;
    }

    // An id token a user may sign in or sign up with: a sign-up claims the token's email for good,
    // so an unverified one must fail before anything is saved.
    public async Task<ClaimsIdentity> ValidateSignInIdToken(string idToken)
    {
        var claimsIdentity = await grayMintIdTokenValidator.ValidateIdToken(idToken);

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.TokenUse, TokenUse.Id))
            throw new AuthenticationException("This is not an id token.");

        if (!claimsIdentity.HasClaim(GrayMintClaimTypes.EmailVerified, "true"))
            throw new AuthenticationException("Email has not been verified.");

        return claimsIdentity;
    }

    public async Task<ApiKey> SignIn(string idToken, RefreshTokenType refreshTokenType)
    {
        var claimsIdentity = await ValidateSignInIdToken(idToken);

        // check user existence
        var userId = await authorizationProvider.GetUserId(ClaimUtil.CreateClaimsPrincipal(claimsIdentity))
                     ?? throw new UnregisteredUserException();

        // our token keeps only the profile claims; anything else the identity provider sent, such as a role
        // or a permission, must never reach the checks that trust our own tokens
        var issuedAt = ClaimUtil.GetRequiredUtcTime(claimsIdentity, JwtRegisteredClaimNames.Iat);
        var signInIdentity = new ClaimsIdentity(claimsIdentity.Claims.Where(x => SignInProfileClaimTypes.Contains(x.Type)));
        ClaimUtil.SetClaim(signInIdentity, new Claim(JwtRegisteredClaimNames.Sub, userId));
        ClaimUtil.SetClaim(signInIdentity, ClaimUtil.CreateClaimTime(JwtRegisteredClaimNames.AuthTime, issuedAt));

        var apiKey = await CreateApiKey(signInIdentity,
            new ApiKeyOptions {
                ValidateOptions = new ValidateOptions { ValidateAuthCode = true, ValidateSubject = true },
                RefreshTokenType = refreshTokenType
            });

        return apiKey;
    }

    public async Task<Token> CreateIdToken(ClaimsIdentity claimsIdentity, ValidateOptions? validateOptions = null)
    {
        var expirationTime = JwtUtil.UtcNow + _authenticationOptions.IdTokenTimeout;
        var token = await CreateToken(claimsIdentity, validateOptions, TokenUse.Id, expirationTime);
        return token;
    }

    public async Task<Uri> GetSignInRedirectUrl(string idToken, string? csrfToken)
    {
        if (_authenticationOptions.SignInRedirectUrl == null)
            throw new InvalidOperationException(
                "TeamController:SignInRedirectUrl has not been configured in app settings.");

        // an identity provider's token only: one of ours would renew itself here, each copy with a new sign-in time
        var claimsIdentity = await grayMintIdTokenValidator.ValidateOpenIdToken(idToken);
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
        var googleClientId = _authenticationOptions.OpenIdProviders.SingleOrDefault(x => x.Name == "Google")?.Audience;
        ArgumentException.ThrowIfNullOrEmpty(googleClientId);

        const string baseUrl = "https://accounts.google.com/gsi/select";
        var query = new Dictionary<string, string?> {
            { "client_id", googleClientId },
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