using System.Security.Claims;

namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public static class RoleAuthorization
{
    public const string RoleClaimType = "graymint-role";
    
    public static Claim CreateRoleClaim(string resourceId, string roleName)
    {
        var roleValue = $"/resources/{resourceId}/roles/{roleName}".ToLower();
        return new Claim(RoleClaimType, roleValue);
    }
}