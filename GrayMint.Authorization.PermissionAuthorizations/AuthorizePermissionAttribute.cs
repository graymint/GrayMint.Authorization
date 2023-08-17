using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GrayMint.Authorization.PermissionAuthorizations;

public class AuthorizePermissionAttribute : AuthorizeAttribute, IAsyncAuthorizationFilter
{
    private readonly PermissionAuthorizationRequirement _requirement;

    public AuthorizePermissionAttribute(string permission)
    {
        _requirement = new PermissionAuthorizationRequirement
        {
            Permission = permission,
        };
    }

    public AuthorizePermissionAttribute(string resourceRouteName, string permission, string? resourceValuePrefix = null)
    {
        _requirement = new PermissionAuthorizationRequirement
        {
            Permission = permission,
            ResourceRouteName = resourceRouteName,
            ResourceValuePrefix = resourceValuePrefix
        };
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        // find policy
        var policyName = PermissionAuthorization.BuildPermissionPolicyName(_requirement.Permission);
        var policy = await context.HttpContext.RequestServices.GetRequiredService<IAuthorizationPolicyProvider>().GetPolicyAsync(policyName);
        if (policy == null)
        {
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
            return;
        }

        // find policy requirement and merge into new one
        var policyPermissionRequirement = policy.Requirements.OfType<PermissionAuthorizationRequirement>().First();
        var requirement = new PermissionAuthorizationRequirement
        {
            Permission = _requirement.Permission,
            ResourceRouteName = _requirement.ResourceRouteName,
            ResourceValuePrefix = string.IsNullOrEmpty(_requirement.ResourceValuePrefix) && _requirement.ResourceRouteName == policyPermissionRequirement.ResourceRouteName
                ? policyPermissionRequirement.ResourceValuePrefix
                : _requirement.ResourceValuePrefix
        };

       // authorize
        var authorizationService = context.HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        var result = await authorizationService.AuthorizeAsync(context.HttpContext.User, context.HttpContext, requirement);

        if (!result.Succeeded)
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}

