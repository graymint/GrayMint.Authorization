using GrayMint.Authorization.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

internal class PermissionAuthorizationHandler : AuthorizationHandler<PermissionAuthorizationRequirement>
{

    private static string GetResourceId(object? resource, PermissionAuthorizationRequirement requirement)
    {
        if (resource is PermissionResource permissionResource)
            return permissionResource.ResourceId;

        if (resource is HttpContext httpContext && !string.IsNullOrEmpty(requirement.ResourceRouteName))
        {
            var resourceId = httpContext.GetRouteValue(requirement.ResourceRouteName)?.ToString();
            if (!string.IsNullOrEmpty(resourceId) && !string.IsNullOrEmpty(requirement.ResourceValuePrefix))
                resourceId = requirement.ResourceValuePrefix + ":" + resourceId;

            return resourceId ?? AuthorizationConstants.RootResourceId;
        }

        return AuthorizationConstants.RootResourceId;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionAuthorizationRequirement requirement)
    {
        // get resource id 
        var resourceId = GetResourceId(context.Resource, requirement);
        var requiredClaim = PermissionAuthorization.BuildPermissionClaim(resourceId, requirement.Permission);

        // check user has requiredClaim
        var succeeded = context.User.Claims.Any(x => x.Type == requiredClaim.Type && x.Value == requiredClaim.Value);

        // result
        if (succeeded)
            context.Succeed(requirement);
        else
            context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));

        return Task.CompletedTask;
    }
}