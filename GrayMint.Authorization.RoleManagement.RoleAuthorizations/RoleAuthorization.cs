using System.Security.Claims;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public static class RoleAuthorization
{
    public const string Policy = "GrayMintRolePolicy";
    public const string RoleClaimType = "app-role";
    public const string PermissionClaimType = "app-permission";

    public static string CreateRoleName(string resourceId, string roleName)
    {
        return $"/resources/{resourceId}/roles/{roleName}".ToLower();
    }

    public static Claim CreateRoleClaim(string resourceId, string roleName)
    {
        return new Claim(RoleClaimType, CreateRoleName(resourceId, roleName));
    }
}