using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GrayMint.Authorization.PermissionAuthorizations;

public class AuthorizePermissionAttribute(string permission)
    : AuthorizeAttribute, IAsyncAuthorizationFilter
{
    /// <summary>
    /// Eg: *, {appId}, appId:{appId}
    /// </summary>
    public string? ResourceRoute { get; init; }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        // authorize
        var authorizationService = context.HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        var requirement = new PermissionAuthorizationRequirement {
            Permission = permission,
            ResourceRoute = ResourceRoute
        };

        var result =
            await authorizationService.AuthorizeAsync(context.HttpContext.User, context.HttpContext, requirement);
        if (!result.Succeeded)
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}