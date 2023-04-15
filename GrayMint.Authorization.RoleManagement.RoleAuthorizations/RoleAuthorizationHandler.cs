using System.Security.Claims;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class RoleAuthorizationHandler : AuthorizationHandler<RolesAuthorizationRequirement>
{
    private readonly RoleAuthorizationOptions _roleAuthorizationOptions;
    private readonly IRoleProvider _roleProvider;

    public RoleAuthorizationHandler(
        IOptions<RoleAuthorizationOptions> roleAuthorizationOptions,
        IRoleProvider roleProvider)
    {
        _roleProvider = roleProvider;
        _roleAuthorizationOptions = roleAuthorizationOptions.Value;
    }

    private string? GetResourceId(object? resource)
    {
        return resource switch
        {
            // get resourceId
            RoleResource roleResource => roleResource.Resource,
            HttpContext httpContext => httpContext.GetRouteValue(_roleAuthorizationOptions.ResourceParamName)?.ToString(),
            _ => null
        };
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, RolesAuthorizationRequirement requirement)
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

        // look for specified resource access
        //todo cache
        var userRoles = await _roleProvider.GetUserRoles(resourceId: resourceId, userId: userId);
        var succeeded = userRoles.Items.Any(x => requirement.AllowedRoles.Any(y => y == x.Role.RoleName));
        
        // look for system resource
        if (!succeeded)
        {
            //todo cache
            userRoles = await _roleProvider.GetUserRoles(resourceId: "*", userId: userId);
            succeeded = userRoles.Items.Any(x => requirement.AllowedRoles.Any(y => y == x.Role.RoleName));
        }

        // result
        if (succeeded)
            context.Succeed(requirement);
        else
            context.Fail(new AuthorizationFailureReason(this, "Access forbidden."));
    }
}