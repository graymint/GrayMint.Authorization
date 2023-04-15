using System.Security.Claims;
using GrayMint.Authorization.RoleManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class RoleAuthorizationService
{
    private readonly IAuthorizationService _authorizationService;
    private readonly IRoleProvider _roleProvider;

    public RoleAuthorizationService(
        IAuthorizationService authorizationService, 
        IRoleProvider roleProvider)
    {
        _authorizationService = authorizationService;
        _roleProvider = roleProvider;
    }

    public async Task<AuthorizationResult> AuthorizePermissionAsync(ClaimsPrincipal user, string? resource, string permission)
    {
        resource ??= await _roleProvider.GetRootResourceId();
        var res = await _authorizationService.AuthorizeAsync(user, new RoleResource(resource), RoleAuthorization.Policy);
        if (!res.Succeeded) return res;

        return await _authorizationService.AuthorizeAsync(user, new RoleResource(resource), 
            new PermissionAuthorizationRequirement(permission));
    }
}