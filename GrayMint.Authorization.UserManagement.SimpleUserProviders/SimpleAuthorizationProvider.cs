using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders;

public class SimpleAuthorizationProvider : IAuthorizationProvider
{
    private readonly IUserProvider _userProvider;

    public SimpleAuthorizationProvider(IUserProvider userProvider)
    {
        _userProvider = userProvider;
    }

    public async Task<string?> GetAuthorizationCode(ClaimsPrincipal principal)
    {
        if (!Guid.TryParse(await GetUserId(principal), out var userId))
            return null;

        var user = await _userProvider.Get(userId);
        return user.AuthorizationCode;
    }

    public async Task<string?> GetUserId(ClaimsPrincipal principal)
    {
        var userIdClaim = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
        if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
        {
            var user = await _userProvider.FindById(userId);
            if (user != null)
                return !user.IsDisabled ? user.UserId.ToString(): throw new UnauthorizedAccessException("User is locked.");
        }

        var emailClaim = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
        if (emailClaim != null)
        {
            var user = await _userProvider.FindByEmail(emailClaim.Value);
            if (user != null)
                return !user.IsDisabled ? user.UserId.ToString(): throw new UnauthorizedAccessException("User is locked.");
        }

        return null;
    }

    public async Task OnAuthenticated(ClaimsPrincipal principal)
    {
        if (!Guid.TryParse(await GetUserId(principal), out var userId))
            return;

        var user = await _userProvider.Get(userId);

        //update profile by claim
        var givenName = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value;
        var surnameName = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Surname)?.Value;

        var updateRequest = new UserUpdateRequest
        {
            FirstName = givenName,
            LastName = surnameName
        };
        if ((givenName != null && user.FirstName != givenName) ||
            (surnameName != null && user.LastName != surnameName))
            await _userProvider.Update(user.UserId, updateRequest);

        // update access time
        if (user.AccessedTime is null || user.AccessedTime < DateTime.UtcNow - TimeSpan.FromMinutes(60))
        {
            if (_userProvider is SimpleUserProvider simpleUserProvider)
                await simpleUserProvider.UpdateAccessedTime(user.UserId);
        }
    }
}