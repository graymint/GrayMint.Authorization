using System.Security.Claims;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

/// <summary>
/// Just add permission claims to user. It doesn't fail the authorization if user doesn't have permission.
/// </summary>
internal class RolePermissionsAuthorizationHandler(IRoleAuthorizationProvider roleAuthorizationProvider)
    : AuthorizationHandler<PermissionAuthorizationRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionAuthorizationRequirement requirement)
    {
        try {
            if (context.User.Identity?.IsAuthenticated == false)
                return;

            // get userId
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return;

            // Add UserPermissions to claims
            var resourceId = PermissionAuthorizationHandler.GetResourceId(context.Resource, requirement.ResourceRoute);
            var userPermissions =
                await roleAuthorizationProvider.GetUserPermissions(resourceId: resourceId, userId: userId);
            var claims = userPermissions.Select(permission =>
                PermissionAuthorization.BuildPermissionClaim(resourceId, permission));
            var identity = new ClaimsIdentity(claims);
            context.User.AddIdentity(identity);
        }
        catch (Exception ex) {
            context.Fail(new AuthorizationFailureReason(this, ex.Message));
        }
    }
}