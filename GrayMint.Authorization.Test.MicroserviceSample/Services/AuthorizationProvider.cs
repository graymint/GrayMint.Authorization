using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.MicroserviceSample.Security;
using GrayMint.Common.Exceptions;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.Test.MicroserviceSample.Services;

public class AuthorizationProvider(
    AppService appService,
    IOptions<AppOptions> appSettings) : IAuthorizationProvider
{
    private readonly AppOptions _appOptions = appSettings.Value;

    public Task<string?> GetUserId(ClaimsPrincipal principal)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        return Task.FromResult(userId);
    }

    public async Task<string?> GetAuthorizationCode(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal) ?? throw new NotExistsException("Could not find userId.");

        if (userId == AuthorizationConstants.SystemUserId)
            return _appOptions.SystemAuthorizationCode;

        var authorizationCode = await appService.GetAuthorizationCode(int.Parse(userId));
        return authorizationCode;
    }

    public async Task OnAuthenticated(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal) ?? throw new NotExistsException("Could not find userId.");
        var claimsIdentity = principal.Identities.First();

        if (userId == AuthorizationConstants.SystemUserId)
        {
            claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(AuthorizationConstants.RootResourceId, Permissions.AppCreate));
            claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(AuthorizationConstants.RootResourceId, Permissions.AppRead));
            claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(AuthorizationConstants.RootResourceId, Permissions.AppWrite));
        }
        else
        {
            claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(userId, Permissions.AppRead));
            claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(userId, Permissions.AppWrite));
        }
    }

    public async Task RestAuthorizationCode(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal) ?? throw new NotExistsException("Could not find userId.");
        if (userId == AuthorizationConstants.SystemUserId)
            throw new NotSupportedException("Could not update system authorization code.");

        var appId = int.Parse(userId);
        await appService.UpdateAuthorizationCode(appId, Guid.NewGuid().ToString());
    }


}