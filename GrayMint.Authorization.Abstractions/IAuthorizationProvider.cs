using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GrayMint.Authorization.Abstractions;

public interface IAuthorizationProvider
{
    public Task<string?> GetAuthorizationCode(ClaimsPrincipal principal);
    Task<Guid?> GetUserId(ClaimsPrincipal principal);
    Task OnAuthenticated(ClaimsPrincipal principal);
}