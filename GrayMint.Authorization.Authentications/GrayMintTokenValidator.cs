using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using GrayMint.Authorization.Abstractions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Authentications;

public class GrayMintTokenValidator
{
    private readonly IAuthorizationProvider _authenticationProvider;
    private readonly IMemoryCache _memoryCache;
    private readonly GrayMintAuthenticationOptions _authenticationOptions;
    private readonly MD5 _md5 = MD5.Create(); 
    public GrayMintTokenValidator(
        IAuthorizationProvider authenticationProvider,
        IMemoryCache memoryCache,
        IOptions<GrayMintAuthenticationOptions> authenticationOptions)
    {
        _authenticationProvider = authenticationProvider;
        _memoryCache = memoryCache;
        _authenticationOptions = authenticationOptions.Value;
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
            var tokenAuthCode = context.Principal.Claims.SingleOrDefault(x => x.Type == GrayMintAuthenticationDefaults.AuthorizationCodeTypeName)?.Value;
            var authCodeCacheKey = $"graymint:auth:token:auth-code:jti={tokenId}";
            if (tokenAuthCode != AuthorizationConstants.AnyAuthCode)
            {
                if (string.IsNullOrEmpty(tokenAuthCode))
                    throw new Exception($"Could not find {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName} in the token.");

                // get authCode and manage cache
                var authCode = await _memoryCache.GetOrCreateAsync(authCodeCacheKey, entry =>
                {
                    entry.SetAbsoluteExpiration(_authenticationOptions.CacheTimeout);
                    return _authenticationProvider.GetAuthorizationCode(context.Principal);
                });

                if (string.IsNullOrEmpty(authCode))
                    throw new Exception($"{GrayMintAuthenticationDefaults.AuthenticationScheme} needs {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName}.");

                if (authCode != tokenAuthCode)
                    throw new Exception($"Invalid {GrayMintAuthenticationDefaults.AuthorizationCodeTypeName}.");
            }

            // update name-identifier
            var userIdCacheKey = $"graymint:auth:token:userid:jti={tokenId}";
            var userId = await _memoryCache.GetOrCreateAsync(userIdCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(_authenticationOptions.CacheTimeout);
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