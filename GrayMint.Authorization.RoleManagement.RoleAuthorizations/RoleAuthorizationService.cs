using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class RoleAuthorizationService
{
    private readonly IAuthorizationService _authorizationService;

    public RoleAuthorizationService(IAuthorizationService authorizationService)
    {
        _authorizationService = authorizationService;
    }

    public async Task<AuthorizationResult> AuthorizePermissionAsync(ClaimsPrincipal user, string? resource, string permission)
    {
        var res = await _authorizationService.AuthorizeAsync(user, new RoleResource(resource), RoleAuthorization.Policy);
        if (!res.Succeeded) return res;

        return await _authorizationService.AuthorizeAsync(user, new RoleResource(resource), 
            new PermissionAuthorizationRequirement(permission));
    }
}