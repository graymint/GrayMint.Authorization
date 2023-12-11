using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.MicroserviceAuthorization;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Authorize]
[Route("/api/v{version:apiVersion}/authorization")]
public class AuthorizationController(MicroserviceAuthorizationService microserviceAuthorizationService) : ControllerBase
{
    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public virtual Task<ApiKey> CreateSystemApiKey([FromForm] string secret)
    {
        return microserviceAuthorizationService.CreateSystemApiKey(secret);
    }

    [HttpPost("system/reset-user-api-key")]
    public virtual Task<ApiKey> ResetUserApiKey(string userId)
    {
        if (User.FindFirstValue(ClaimTypes.NameIdentifier) != AuthorizationConstants.SystemUserId)
            throw new UnauthorizedAccessException("Only system user can reset other user api key.");

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
        return microserviceAuthorizationService.ResetApiKey(new ClaimsPrincipal(claimsIdentity));
    }

    [HttpPost("current/reset-api-key")]
    public virtual Task<ApiKey> ResetCurrentUserApiKey()
    {
        return microserviceAuthorizationService.ResetApiKey(User);
    }
}