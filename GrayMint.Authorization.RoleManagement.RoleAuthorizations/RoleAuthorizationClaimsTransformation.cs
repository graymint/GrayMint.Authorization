using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authentication;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

internal class RoleAuthorizationClaimsTransformation : IClaimsTransformation
{
    private readonly IRoleProvider _roleProvider;
    private readonly IAuthorizationProvider _authorizationProvider;

    public RoleAuthorizationClaimsTransformation(
        IRoleProvider roleProvider,
        IAuthorizationProvider authorizationProvider)
    {
        _roleProvider = roleProvider;
        _authorizationProvider = authorizationProvider;
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        // add simple roles to app-role claims
        var resourceId = _roleProvider.GetRootResourceId();
        var userId = await _authorizationProvider.GetUserId(principal);
        if (userId == null) return principal;

        //get userRoles
        var userRoles = await  _roleProvider.GetUserRoles(userId: userId.Value);

        // Add the following claims
        // /apps/*/RoleName
        // /apps/appId/RoleName
        var claimsIdentity = new ClaimsIdentity();
        foreach (var userRole in userRoles.Items)
        {
            // add GrayMint claim
            claimsIdentity.AddClaim(RoleAuthorization.CreateRoleClaim(userRole.ResourceId, userRole.Role.RoleName));

            // add standard claim role
            if (userRole.ResourceId == resourceId && !claimsIdentity.HasClaim(ClaimTypes.Role, userRole.Role.RoleName))
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, userRole.Role.RoleName));
        }

        // update nameIdentifier to userId
        if (principal.Identity is ClaimsIdentity identity)
        {
            identity.RemoveClaim(identity.FindFirst(ClaimTypes.NameIdentifier));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId.Value.ToString()));
        }
        else
            claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId.Value.ToString()));

        principal.AddIdentity(claimsIdentity);
        return principal;
    }
}