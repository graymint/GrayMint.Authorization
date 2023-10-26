using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.Helper;

public class TestAuthenticationProvider : IAuthorizationProvider
{
    private readonly IServiceScopeFactory _serviceScopeFactory;

    public TestAuthenticationProvider(IServiceScopeFactory serviceScopeFactory)
    {
        _serviceScopeFactory = serviceScopeFactory;
    }

    public async Task<string?> GetAuthorizationCode(ClaimsPrincipal principal)
    {
        if (principal.FindFirstValue("test_authenticated") == "1")
            return "test_1234";

        await using var scope = _serviceScopeFactory.CreateAsyncScope();
        var original = scope.ServiceProvider.GetServices<IAuthorizationProvider>();
        return await original.First(x => x != this).GetAuthorizationCode(principal);
    }

    public async Task<string?> GetUserId(ClaimsPrincipal principal)
    {
        await using var scope = _serviceScopeFactory.CreateAsyncScope();
        var original = scope.ServiceProvider.GetServices<IAuthorizationProvider>();
        return await original.First(x => x != this).GetUserId(principal);
    }

    public async Task OnAuthenticated(ClaimsPrincipal principal)
    {
        await using var scope = _serviceScopeFactory.CreateAsyncScope();
        var original = scope.ServiceProvider.GetServices<IAuthorizationProvider>();
        await original.First(x => x != this).OnAuthenticated(principal);
    }
}