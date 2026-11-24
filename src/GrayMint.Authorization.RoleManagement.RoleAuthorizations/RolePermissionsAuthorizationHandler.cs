using System.Security.Claims;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

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

            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
                return;

            // the request's token where the resource is its HttpContext; a check made outside a request has none
            var cancellationToken = (context.Resource as HttpContext)?.RequestAborted ?? CancellationToken.None;
            var resourceId = PermissionAuthorizationHandler.GetResourceId(context.Resource, requirement.ResourceRoute);
            var userPermissions = await roleAuthorizationProvider.GetUserPermissions(resourceId: resourceId,
                userId: userId, cancellationToken);

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