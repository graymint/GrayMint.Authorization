using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class AuthorizePermissionAttribute : AuthorizeAttribute, IAsyncAuthorizationFilter
{
    private readonly string _permission;

    public AuthorizePermissionAttribute(string permission)
    {
        _permission = permission;
    }

    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var authorizationService = context.HttpContext.RequestServices.GetRequiredService<IAuthorizationService>();
        var result = await authorizationService.AuthorizeAsync(context.HttpContext.User, context.HttpContext,
            new PermissionAuthorizationRequirement(_permission));

        if (!result.Succeeded)
            context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}