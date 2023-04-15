using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

internal class PermissionAuthorizationRequirement : IAuthorizationRequirement
{
    public string PermissionId { get; }
    public PermissionAuthorizationRequirement(string permissionId)
    {
        PermissionId = permissionId;
    }
}