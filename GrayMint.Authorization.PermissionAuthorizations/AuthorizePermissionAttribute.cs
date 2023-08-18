using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GrayMint.Authorization.PermissionAuthorizations;

public class AuthorizePermissionAttribute : AuthorizeAttribute, IAsyncAuthorizationFilter
{
    private readonly string _permission;

    /// <summary>
    /// Eg: *, {appId}, appId:{appId}
    /// </summary>
    public string? ResourceRoute { get; init; }

    public AuthorizePermissionAttribute(string permission)
    {
        _permission = permission;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        // authorize
        var authorizationService = context.HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        var requirement = new PermissionAuthorizationRequirement
        {
            Permission = _permission,
            ResourceRoute = ResourceRoute
        };
        var result = await authorizationService.AuthorizeAsync(context.HttpContext.User, context.HttpContext, requirement);

        if (!result.Succeeded)
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}

