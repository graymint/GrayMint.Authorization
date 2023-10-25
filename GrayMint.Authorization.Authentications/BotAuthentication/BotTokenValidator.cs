using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
    private readonly MD5 _md5 = MD5.Create(); 
    public BotTokenValidator(
        IAuthorizationProvider authenticationProvider,
        IMemoryCache memoryCache,
        IOptions<BotAuthenticationOptions> botAuthenticationOptions)
    {
        _authenticationProvider = authenticationProvider;
        _memoryCache = memoryCache;
        _botAuthenticationOptions = botAuthenticationOptions.Value;
    }

    private string ComputeHash(string input)
    {
        var hashBytes = _md5.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    public async Task Validate(TokenValidatedContext context)
    {
        try
        {
            if (context.Principal == null)
                throw new Exception("Principal has not been validated.");

            var tokenId = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Jti);
            if (string.IsNullOrEmpty(tokenId)) tokenId = ComputeHash(((JwtSecurityToken)context.SecurityToken).RawData); // todo: for compatibility

            // check authCode
            var tokenAuthCode = context.Principal.Claims.SingleOrDefault(x => x.Type == BotAuthenticationDefaults.AuthorizationCodeTypeName)?.Value;
            var authCodeCacheKey = $"graymint:auth:bot:auth-code:jti={tokenId}";
            if (tokenAuthCode != AuthorizationConstants.AnyAuthCode)
            {
                if (string.IsNullOrEmpty(tokenAuthCode))
                    throw new Exception($"Could not find {BotAuthenticationDefaults.AuthorizationCodeTypeName} in the token.");

                // get authCode and manage cache
                var authCode = await _memoryCache.GetOrCreateAsync(authCodeCacheKey, entry =>
                {
                    entry.SetAbsoluteExpiration(_botAuthenticationOptions.CacheTimeout);
                    return _authenticationProvider.GetAuthorizationCode(context.Principal);
                });

                if (string.IsNullOrEmpty(authCode))
                    throw new Exception($"{BotAuthenticationDefaults.AuthenticationScheme} needs {BotAuthenticationDefaults.AuthorizationCodeTypeName}.");

                if (authCode != tokenAuthCode)
                    throw new Exception($"Invalid {BotAuthenticationDefaults.AuthorizationCodeTypeName}.");
            }

            // update name-identifier
            var userIdCacheKey = $"graymint:auth:bot:userid:jti={tokenId}";
            var userId = await _memoryCache.GetOrCreateAsync(userIdCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_botAuthenticationOptions.CacheTimeout);
                return _authenticationProvider.GetUserId(context.Principal);
            });
            if (userId != null)
            {
                AuthorizationUtil.UpdateNameIdentifier(context.Principal, userId);
                AuthorizationCache.AddKey(_memoryCache, userId, userIdCacheKey);
                AuthorizationCache.AddKey(_memoryCache, userId, authCodeCacheKey);
            }

            await _authenticationProvider.OnAuthenticated(context.Principal);
        }
        catch (Exception ex)
        {
            context.Fail(ex.Message);
        }
    }
}