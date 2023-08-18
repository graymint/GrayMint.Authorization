using System.Security.Claims;

namespace GrayMint.Authorization.PermissionAuthorizations;

public static class PermissionAuthorization
{
    public const string PermissionClaimType = "graymint-permission";

    public static Claim BuildPermissionClaim(string resourceId, string permission)
    {
        var claimValue = $"/resources/{resourceId}/permissions/{permission}";
        return new Claim(PermissionClaimType, claimValue);
    }

    public static string BuildPermissionPolicyName(string permission)
    {
        return $"graymint:permission:{permission}Policy";
    }
}