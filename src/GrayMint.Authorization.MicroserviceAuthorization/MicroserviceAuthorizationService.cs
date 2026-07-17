using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Dtos;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.MicroserviceAuthorization;

public class MicroserviceAuthorizationService(
    GrayMintAuthentication grayMintAuthentication,
    IAuthorizationProvider authorizationProvider,
    UserAuthorizationCache userAuthorizationCache,
    IOptions<GrayMintAuthenticationOptions> authenticationOptions)
{
    private readonly GrayMintAuthenticationOptions _authenticationOptions = authenticationOptions.Value;

    public async Task<ApiKey> ResetApiKey(ClaimsPrincipal claimsPrincipal)
    {
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? throw new UnauthorizedAccessException("Could not find user id in claims.");

        // reset authorization code
        await authorizationProvider.RestAuthorizationCode(claimsPrincipal);
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(claimsPrincipal);

        // clear user cache
        userAuthorizationCache.ClearUserItems(userId);

        // create ClaimsIdentity
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userId));
        if (authorizationCode != null)
            claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.AuthCode, authorizationCode));

        // create api key
        var apiKey = await grayMintAuthentication.CreateApiKey(claimsIdentity, new ApiKeyOptions {
            ValidateOptions = new ValidateOptions {
                ValidateAuthCode = true,
                ValidateSubject = false
            }
        });

        return apiKey;
    }

    public async Task<ApiKey> CreateSystemApiKey(string secret)
    {
        if (!Convert.FromBase64String(secret).SequenceEqual(_authenticationOptions.Secret))
            throw new UnauthorizedAccessException("Bad secret.");

        // get authorization code
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, AuthorizationConstants.SystemUserId));
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(claimsIdentity))
                                ?? throw new KeyNotFoundException("Could not find authorization code for system user.");

        // create ClaimsIdentity
        claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, AuthorizationConstants.SystemUserId));
        claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.AuthCode, authorizationCode));

        // create api key
        var apiKey = await grayMintAuthentication.CreateApiKey(claimsIdentity, new ApiKeyOptions {
            ValidateOptions = new ValidateOptions {
                ValidateAuthCode = true,
                ValidateSubject = false
            }
        });

        return apiKey;
    }
}