using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

internal class PermissionAuthorizationHandler : AuthorizationHandler<PermissionAuthorizationRequirement>
{
    private readonly RoleAuthorizationOptions _roleAuthorizationOptions;
    private readonly IRoleProvider _roleProvider;

    public PermissionAuthorizationHandler(
        IOptions<RoleAuthorizationOptions> options,
        IRoleProvider roleProvider)
    {
        _roleProvider = roleProvider;
        _roleAuthorizationOptions = options.Value;
    }

    private string? GetResourceId(object? resource)
    {
        return resource switch
        {
            // get resourceId
            RoleResource roleResource =>
                roleResource.Resource,

            HttpContext httpContext =>
                httpContext.GetRouteValue(_roleAuthorizationOptions.ResourceParamName)?.ToString()
                ?? _roleProvider.GetRootResourceId(),

            _ => null
        };
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionAuthorizationRequirement requirement)
    {
        // get resource id 
        var resourceId = GetResourceId(context.Resource);
        if (resourceId == null)
        {
            context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));
            return;
        }

        // get userId
        var userIdString = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userIdString == null || !Guid.TryParse(userIdString, out var userId))
        {
            context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));
            return;
        }

        // get user permissions
        var userPermissions = await _roleProvider.GetUserPermissions(resourceId: resourceId, userId: userId);

        // validate roles
        var succeeded = userPermissions.Any(x => x == requirement.PermissionId);
        if (succeeded)
            context.Succeed(requirement);
        else
            context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));
    }
}