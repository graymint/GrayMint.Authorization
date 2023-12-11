using System.Security.Claims;

namespace GrayMint.Authorization.MicroserviceAuthorization;

[ApiVersion("1")]
[ApiController]
[Authorize]
[Route("/api/v{version:apiVersion}/authorization")]
public class SimpleAuthorizationController(MicroserviceAuthorizationService resourceAuthorizationService) : ControllerBase
{
    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public virtual Task<ApiKey> CreateSystemApiKey([FromForm] string secret)
    {
        return resourceAuthorizationService.CreateSystemApiKey(secret);
    }

    [HttpPost("system/reset-user-api-key")]
    public virtual Task<ApiKey> ResetUserApiKey(string userId)
    {
        if (User.FindFirstValue(ClaimTypes.NameIdentifier) != AuthorizationConstants.SystemUserId)
            throw new UnauthorizedAccessException("Only system user can reset other user api key.");

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
        return resourceAuthorizationService.ResetApiKey(new ClaimsPrincipal(claimsIdentity));
    }

    [HttpPost("current/reset-api-key")]
    public virtual Task<ApiKey> ResetCurrentUserApiKey()
    {
        return resourceAuthorizationService.ResetApiKey(User);
    }
}