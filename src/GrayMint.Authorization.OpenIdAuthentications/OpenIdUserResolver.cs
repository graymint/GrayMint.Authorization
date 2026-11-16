using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;

namespace GrayMint.Authorization.OpenIdAuthentications;

// Finds the user of a caller whose access token its provider's scheme has checked.
public sealed class OpenIdUserResolver(UserBindingStore bindingStore, IAuthorizationProvider authorizationProvider)
{
    // True names the user in the principal, where the roles and permissions look for it. False for an account
    // that is tied to no user, or whose user is gone or locked.
    public async Task<bool> TryResolve(string providerName, ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        var subject = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (string.IsNullOrEmpty(subject))
            return false;

        var userId = await bindingStore.FindUserId(providerName, subject, cancellationToken);
        if (userId == null)
            return false;

        AuthorizationUtil.UpdateNameIdentifier(principal, userId);

        // The user as it is now. Only the very user the account is tied to will do: a provider of users may
        // look further than the id, such as for an address the token carries, and an address ties nobody.
        var foundUserId = await FindUserId(principal);
        if (foundUserId != userId)
            return false;

        await authorizationProvider.OnAuthenticated(principal);
        return true;
    }

    // null for a locked user, which the provider of users says by an exception of this kind
    private async Task<string?> FindUserId(ClaimsPrincipal principal)
    {
        try {
            return await authorizationProvider.GetUserId(principal);
        }
        catch (UnauthorizedAccessException) {
            return null;
        }
    }
}
