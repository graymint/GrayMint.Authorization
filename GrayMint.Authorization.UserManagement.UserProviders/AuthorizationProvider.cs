using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.UserManagement.UserProviders;

public class AuthorizationProvider : IAuthorizationProvider
{
    private readonly IUserProvider _userProvider;

    public AuthorizationProvider(IUserProvider userProvider)
    {
        _userProvider = userProvider;
    }

    public async Task<string?> GetAuthorizationCode(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal);
        if (userId is null)
            return null;

        var user = await _userProvider.Get(userId);
        return user.AuthorizationCode;
    }

    public async Task<string?> GetUserId(ClaimsPrincipal principal)
    {
        var userId = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
        if (userId != null)
        {
            var user = await _userProvider.FindById(userId);
            if (user != null)
                return !user.IsDisabled ? user.UserId : throw new UnauthorizedAccessException("User is locked.");
        }

        var emailClaim = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
        if (emailClaim != null)
        {
            var user = await _userProvider.FindByEmail(emailClaim.Value);
            if (user != null)
                return !user.IsDisabled ? user.UserId : throw new UnauthorizedAccessException("User is locked.");
        }

        return null;
    }

    public async Task OnAuthenticated(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal);
        if (userId is null)
            return;

        var user = await _userProvider.Get(userId);

        // update access time
        if (user.AccessedTime is null || user.AccessedTime < DateTime.UtcNow - TimeSpan.FromMinutes(60))
        {
            if (_userProvider is UserProvider userProvider)
                await userProvider.UpdateAccessedTime(user.UserId);
        }
    }
}