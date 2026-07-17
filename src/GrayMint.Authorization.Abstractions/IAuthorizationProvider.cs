using System.Security.Claims;

namespace GrayMint.Authorization.Abstractions;

public interface IAuthorizationProvider
{
    Task<string?> GetAuthorizationCode(ClaimsPrincipal principal);
    Task<string?> GetUserId(ClaimsPrincipal principal);
    Task OnAuthenticated(ClaimsPrincipal principal);
    Task RestAuthorizationCode(ClaimsPrincipal principal);
}