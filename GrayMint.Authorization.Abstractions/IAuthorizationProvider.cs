using System.Security.Claims;

namespace GrayMint.Authorization.Abstractions;

public interface IAuthorizationProvider
{
    public Task<string?> GetAuthorizationCode(ClaimsPrincipal principal);
    Task<string?> GetUserId(ClaimsPrincipal principal);
    Task OnAuthenticated(ClaimsPrincipal principal);
}