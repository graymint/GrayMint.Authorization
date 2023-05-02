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
        var userId = await GetUserId(principal);
        if (userId == null) return null;
        var user = await _userProvider.Get(userId.Value);
        return user.AuthorizationCode;
    }

    public async Task<Guid?> GetUserId(ClaimsPrincipal principal)
    {
        var email = principal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email)?.Value;
        if (email == null) return null;
        var user = await _userProvider.FindByEmail(email);
        return user?.UserId;
    }

    public async Task OnAuthenticated(ClaimsPrincipal principal)
    {
        var userId = await GetUserId(principal);
        if (userId == null)
            return;

        var user = await _userProvider.Get(userId.Value);

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