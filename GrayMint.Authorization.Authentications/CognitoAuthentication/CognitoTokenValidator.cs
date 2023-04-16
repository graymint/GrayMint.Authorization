using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using GrayMint.Common.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications.CognitoAuthentication;

public class CognitoTokenValidator
{
    private readonly HttpClient _httpClient;
    private readonly IOptions<CognitoAuthenticationOptions> _cognitoOptions;
    private readonly IMemoryCache _memoryCache;

    public CognitoTokenValidator(HttpClient httpClient,
        IOptions<CognitoAuthenticationOptions> cognitoOptions,
        IMemoryCache memoryCache)
    {
        _httpClient = httpClient;
        _cognitoOptions = cognitoOptions;
        _memoryCache = memoryCache;
    }

    private async Task<OpenIdUserInfo> GetUserInfoFromAccessToken(TokenValidatedContext context)
    {
        var jwtSecurityToken = (JwtSecurityToken)context.SecurityToken;
        var accessToken = jwtSecurityToken.RawData;

        // get from cache
        var accessTokenHash = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(accessToken));
        var cacheKey = "OpenIdUserInfo/" + Convert.ToBase64String(accessTokenHash);
        if (_memoryCache.TryGetValue<OpenIdUserInfo>(cacheKey, out var userInfo) && userInfo != null)
            return userInfo;

        // get from authority
        if (context.Options.ConfigurationManager == null)
            throw new UnauthorizedAccessException("ConfigurationManager is not set.");
        var configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(CancellationToken.None);
        var tokenUse = jwtSecurityToken.Claims.FirstOrDefault(x => x.Type == "token_use")?.Value
                       ?? throw new UnauthorizedAccessException("Could not find token_use.");

        // get userInfo message from id token
        OpenIdUserInfo openIdUserInfo;
        if (tokenUse == "id")
        {
            openIdUserInfo = new OpenIdUserInfo
            {
                Sub = jwtSecurityToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Sub).Value,
                Email = jwtSecurityToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email)?.Value,
                EmailVerified = jwtSecurityToken.Claims.FirstOrDefault(x => x.Type == "email_verified")?.Value,
            };
        }
        else
        {
            // get userInfo message access token
            if (!jwtSecurityToken.Claims.Any(x => x.Type == "scope" && x.Value.Split(' ').Contains("openid")))
                throw new UnauthorizedAccessException("openid scope was expected.");

            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, configuration.UserInfoEndpoint);
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, accessToken);
            var httpResponseMessage = await _httpClient.SendAsync(httpRequestMessage);
            httpResponseMessage.EnsureSuccessStatusCode();
            var json = await httpResponseMessage.Content.ReadAsStringAsync();
            openIdUserInfo = GmUtil.JsonDeserialize<OpenIdUserInfo>(json);
        }

        _memoryCache.Set(cacheKey, openIdUserInfo, _cognitoOptions.Value.CacheTimeout);
        return openIdUserInfo;
    }

    public async Task Validate(TokenValidatedContext context)
    {
        if (context.Principal == null)
        {
            context.Fail("Principal does not exist.");
            return;
        }

        // validate audience or client
        var jwtSecurityToken = (JwtSecurityToken)context.SecurityToken;
        var tokenUse = jwtSecurityToken.Claims.FirstOrDefault(x => x.Type == "token_use")?.Value 
                       ?? throw new UnauthorizedAccessException("Could not find token_use.");

        if (tokenUse != "access" && tokenUse != "id") 
            throw new UnauthorizedAccessException("Unknown token_use.");

        // validate aud for id token
        if (tokenUse == "id" && !context.Principal.HasClaim(x => x.Type == "aud" && x.Value == _cognitoOptions.Value.CognitoClientId))
        {
            context.Fail("client_id does not match");
            return;
        }

        // validate client_id for access token
        if (tokenUse == "access" && !context.Principal.HasClaim(x => x.Type == "client_id" && x.Value == _cognitoOptions.Value.CognitoClientId))
        {
            context.Fail("client_id does not match");
            return;
        }

        // get user_info from authority by AccessToken
        var userInfo = await GetUserInfoFromAccessToken(context);
        if (userInfo.EmailVerified != "true")
        {
            context.Fail("User's email is not verified.");
            return;
        }

        // add claims
        var claimsIdentity = new ClaimsIdentity();

        // add email claim
        var email = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Email);
        if (string.IsNullOrEmpty(email)) email = userInfo.Email;
        if (!string.IsNullOrEmpty(email))
        {
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Email, email));
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        }

        var name = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Name);
        if (!string.IsNullOrEmpty(name))
            claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Name, name));

        // Convert cognito roles to standard roles
        foreach (var claim in context.Principal.Claims.Where(x => x.Type == "cognito:groups"))
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, _cognitoOptions.Value.CognitoRolePrefix + claim.Value));

        context.Principal?.AddIdentity(claimsIdentity);
    }

    private class OpenIdUserInfo
    {
        [JsonPropertyName("sub")]

        // ReSharper disable once UnusedAutoPropertyAccessor.Local
        // ReSharper disable once UnusedMember.Local
        public string Sub { get; init; } = default!;

        // ReSharper disable once UnusedAutoPropertyAccessor.Local
        [JsonPropertyName("email_verified")]
        public string? EmailVerified { get; init; }

        // ReSharper disable once UnusedAutoPropertyAccessor.Local
        [JsonPropertyName("email")]
        public string? Email { get; init; }

        // ReSharper disable once UnusedMember.Local
        [JsonPropertyName("username")]
        public string? Name { get; init; }
    }
}