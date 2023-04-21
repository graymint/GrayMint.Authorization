using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications.BotAuthentication;

public class BotTokenValidator
{
    private readonly IAuthorizationProvider _authenticationProvider;
    private readonly IMemoryCache _memoryCache;
    private readonly BotAuthenticationOptions _botAuthenticationOptions;
    public BotTokenValidator(
        IAuthorizationProvider authenticationProvider,
        IMemoryCache memoryCache,
        IOptions<BotAuthenticationOptions> botAuthenticationOptions)
    {
        _authenticationProvider = authenticationProvider;
        _memoryCache = memoryCache;
        _botAuthenticationOptions = botAuthenticationOptions.Value;
    }

    public async Task Validate(TokenValidatedContext context)
    {
        try
        {
            if (context.Principal == null)
                throw new Exception("Principal has not been validated.");

            var tokenId = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Jti);

            // get authCode and manage cache
            var authCodeCacheKey = $"graymint:auth:bot:auth-code:jti={tokenId}";
            var authCode = await _memoryCache.GetOrCreateAsync(authCodeCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_botAuthenticationOptions.CacheTimeout);
                return _authenticationProvider.GetAuthorizationCode(context.Principal);
            });

            if (string.IsNullOrEmpty(authCode))
                throw new Exception($"{BotAuthenticationDefaults.AuthenticationScheme} needs {BotAuthenticationDefaults.AuthorizationCodeTypeName}.");

            // deserialize access token
            var tokenAuthCode = context.Principal.Claims.SingleOrDefault(x => x.Type == BotAuthenticationDefaults.AuthorizationCodeTypeName)?.Value;
            if (string.IsNullOrEmpty(tokenAuthCode))
                throw new Exception($"Could not find {BotAuthenticationDefaults.AuthorizationCodeTypeName} in the token.");

            if (authCode != tokenAuthCode)
                throw new Exception($"Invalid {BotAuthenticationDefaults.AuthorizationCodeTypeName}.");

            // update name-identifier
            var userIdCacheKey = $"graymint:auth:bot:userid:jti={tokenId}";
            var userId = await _memoryCache.GetOrCreateAsync(userIdCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_botAuthenticationOptions.CacheTimeout);
                return _authenticationProvider.GetUserId(context.Principal);
            });
            if (userId != null)
            {
                AuthorizationUtil.UpdateNameIdentifier(context.Principal, userId.Value);
                AuthorizationCache.AddKey(_memoryCache, userId.Value, userIdCacheKey);
                AuthorizationCache.AddKey(_memoryCache, userId.Value, authCodeCacheKey);
            }

            await _authenticationProvider.OnAuthenticated(context.Principal);
        }
        catch (Exception ex)
        {
            context.Fail(ex.Message);
        }
    }
}