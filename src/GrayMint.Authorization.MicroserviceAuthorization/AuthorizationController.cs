using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.Dtos;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.MicroserviceAuthorization;

/// <summary>
/// API keys, whose access token every other request takes.
/// </summary>
/// <remarks>
/// The access token is sent as `Authorization: Bearer &lt;token&gt;`. The system, the caller that holds the service's
/// signing secret, signs its own tokens with it or gets one here. A token carries its user's authorization code, so a
/// new code ends every earlier token of that user.
/// </remarks>
// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Authorize]
[Route("/api/authorization")]
public class AuthorizationController(MicroserviceAuthorizationService microserviceAuthorizationService) : ControllerBase
{
    /// <summary>
    /// Get an API key for the system
    /// </summary>
    /// <remarks>
    /// Takes the service's signing secret and answers with an access token for the system, without a refresh token;
    /// it lasts as long as the service's access tokens do. Refused unless the service's `AllowSystemApiKey` setting
    /// is on, as it is in Development when unset.
    /// </remarks>
    /// <param name="secret">The service's signing secret, as base64.</param>
    /// <returns>The system's API key.</returns>
    [HttpPost("system/api-key")]
    [AllowAnonymous]
    public virtual Task<ApiKey> CreateSystemApiKey([FromForm] string secret)
    {
        return microserviceAuthorizationService.CreateSystemApiKey(secret);
    }

    /// <summary>
    /// Get a new API key for a user
    /// </summary>
    /// <remarks>
    /// For the system alone. The user gets a new authorization code, so every earlier token of the user stops
    /// working, and the answer is the user's new API key.
    /// </remarks>
    /// <param name="userId">The user whose API key to replace.</param>
    /// <returns>The user's new API key, shown only here.</returns>
    [HttpPost("system/reset-user-api-key")]
    public virtual Task<ApiKey> ResetUserApiKey(string userId)
    {
        if (User.FindFirstValue(ClaimTypes.NameIdentifier) != AuthorizationConstants.SystemUserId)
            throw new UnauthorizedAccessException("Only system user can reset other user api key.");

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId));
        return microserviceAuthorizationService.ResetApiKey(new ClaimsPrincipal(claimsIdentity));
    }

    /// <summary>
    /// Get a new API key for yourself
    /// </summary>
    /// <remarks>
    /// You get a new authorization code, so every earlier token of yours stops working, the one of this request too,
    /// and the answer is your new API key. The service's authorization provider may refuse it, as for a caller whose
    /// code is in the service's settings.
    /// </remarks>
    /// <returns>Your new API key, shown only here.</returns>
    [HttpPost("current/reset-api-key")]
    public virtual Task<ApiKey> ResetCurrentUserApiKey()
    {
        return microserviceAuthorizationService.ResetApiKey(User);
    }
}