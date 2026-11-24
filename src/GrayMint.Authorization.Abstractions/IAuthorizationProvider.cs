using System.Security.Claims;

namespace GrayMint.Authorization.Abstractions;

public interface IAuthorizationProvider
{
    Task<string?> GetAuthorizationCode(ClaimsPrincipal principal, CancellationToken cancellationToken);
    Task<string?> GetUserId(ClaimsPrincipal principal, CancellationToken cancellationToken);
    Task OnAuthenticated(ClaimsPrincipal principal, CancellationToken cancellationToken);
    Task ResetAuthorizationCode(ClaimsPrincipal principal, CancellationToken cancellationToken);
}