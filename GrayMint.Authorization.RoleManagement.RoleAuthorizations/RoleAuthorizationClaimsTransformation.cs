using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authentication;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

internal class RoleAuthorizationClaimsTransformation(
    IRoleAuthorizationProvider roleAuthorizationProvider,
    IAuthorizationProvider authorizationProvider)
    : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        // add roles to app-role claims
        var userId = await authorizationProvider.GetUserId(principal);
        if (userId == null)
            return principal;

        //get userRoles
        var userRoles = await roleAuthorizationProvider.GetUserRoles(new UserRoleCriteria { UserId = userId });

        // Add the following claims
        // /resources/*/RoleName
        // /resources/appId/RoleName
        var claimsIdentity = new ClaimsIdentity();
        foreach (var userRole in userRoles)
        {
            // add GrayMint claim
            const string rootResourceId = AuthorizationConstants.RootResourceId;
            claimsIdentity.AddClaim(RoleAuthorization.CreateRoleClaim(userRole.ResourceId, userRole.Role.RoleName));

            // add standard claim role
            if (userRole.ResourceId.Equals(rootResourceId, StringComparison.OrdinalIgnoreCase) && !claimsIdentity.HasClaim(ClaimTypes.Role, userRole.Role.RoleName))
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, userRole.Role.RoleName));
        }

        // update nameIdentifier to userId
        AuthorizationUtil.UpdateNameIdentifier(principal, userId);

        principal.AddIdentity(claimsIdentity);
        return principal;
    }
}