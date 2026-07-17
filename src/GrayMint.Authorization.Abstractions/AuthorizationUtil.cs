using System.Security.Claims;
using System.Security.Principal;

namespace GrayMint.Authorization.Abstractions;

public static class AuthorizationUtil
{
    public static void UpdateNameIdentifier(IPrincipal principal, string userId)
    {
        // update name-identifier
        if (principal.Identity is ClaimsIdentity { IsAuthenticated: true } identity) {
            var nameIdentifierClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
            if (nameIdentifierClaim != null)
                identity.RemoveClaim(nameIdentifierClaim);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
        }
    }
}