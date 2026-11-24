using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Dtos;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.MicroserviceAuthorization;

public class MicroserviceAuthorizationService(
    GrayMintAuthentication grayMintAuthentication,
    IAuthorizationProvider authorizationProvider,
    UserAuthorizationCache userAuthorizationCache,
    IOptions<GrayMintAuthenticationOptions> authenticationOptions,
    IHostEnvironment hostEnvironment)
{
    private readonly GrayMintAuthenticationOptions _authenticationOptions = authenticationOptions.Value;

    public async Task<ApiKey> ResetApiKey(ClaimsPrincipal claimsPrincipal, CancellationToken cancellationToken)
    {
        var userId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? throw new UnauthorizedAccessException("Could not find user id in claims.");

        await authorizationProvider.ResetAuthorizationCode(claimsPrincipal, cancellationToken);
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(claimsPrincipal, cancellationToken);

        userAuthorizationCache.ClearUserItems(userId);

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, userId));
        if (authorizationCode != null)
            claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.AuthCode, authorizationCode));

        var apiKey = await grayMintAuthentication.CreateApiKey(claimsIdentity, new ApiKeyOptions {
            ValidateOptions = new ValidateOptions {
                ValidateAuthCode = true,
                ValidateSubject = false
            }
        }, cancellationToken);

        return apiKey;
    }

    public async Task<ApiKey> CreateSystemApiKey(string secret, CancellationToken cancellationToken)
    {
        // checked before the secret, so a server where it is off never even compares it
        if (!_authenticationOptions.IsSystemApiKeyAllowed(hostEnvironment.IsDevelopment()))
            throw new UnauthorizedAccessException("The system api key is disabled.");

        if (!_authenticationOptions.MatchesSecret(secret))
            throw new UnauthorizedAccessException("Bad secret.");

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, AuthorizationConstants.SystemUserId));
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(claimsIdentity),
            cancellationToken)
                                ?? throw new KeyNotFoundException("Could not find authorization code for system user.");

        claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, AuthorizationConstants.SystemUserId));
        claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.AuthCode, authorizationCode));

        var apiKey = await grayMintAuthentication.CreateApiKey(claimsIdentity, new ApiKeyOptions {
            ValidateOptions = new ValidateOptions {
                ValidateAuthCode = true,
                ValidateSubject = false
            }
        }, cancellationToken);

        return apiKey;
    }
}