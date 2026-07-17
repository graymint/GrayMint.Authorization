using System.Net.Mime;
using System.Security.Authentication;
using System.Text;
using System.Web;
using GrayMint.Authorization.Authentications.Controllers.Dtos;
using GrayMint.Authorization.Authentications.Controllers.Services;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.UserManagement.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Authentications.Controllers.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Authorize]
[Route("/api/authentication")]
public class AuthenticationController(
    AuthenticationService authenticationService,
    GrayMintAuthentication grayMintAuthentication)
    : ControllerBase
{
    [HttpGet("current")]
    [Authorize]
    public virtual async Task<User> GetCurrentUser()
    {
        var userId = await authenticationService.GetUserId(User);
        var ret = await authenticationService.GetUser(userId);
        return ret;
    }

    [HttpPost("current/signout-all")]
    [Authorize]
    public virtual async Task SignOutAll()
    {
        var userId = await authenticationService.GetUserId(User);
        await authenticationService.ResetAuthorizationCode(userId);
    }

    [HttpPost("current/reset-api-key")]
    [Authorize]
    public virtual async Task<ApiKey> ResetCurrentUserApiKey()
    {
        var userId = await authenticationService.GetUserId(User);
        var res = await authenticationService.ResetApiKey(userId);
        return res;
    }

    [HttpPost("signin")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> SignIn(SignInRequest request)
    {
        var apiKey = await authenticationService.SignIn(request);
        return apiKey;
    }

    [HttpPost("signup")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> SignUp(SignUpRequest request)
    {
        var apiKey = await authenticationService.SignUp(request);
        return apiKey;
    }

    [HttpPost("refresh-token")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> RefreshToken(RefreshTokenRequest request)
    {
        var apiKey = await grayMintAuthentication.RefreshToken(request.RefreshToken);
        return apiKey;
    }

    [HttpPost("external/google/signin-handler")]
    [AllowAnonymous]
    public async Task<IActionResult> GoogleSignInHandler()
    {
        // read all request to string
        using var reader = new StreamReader(Request.Body, Encoding.UTF8);
        var queryString = await reader.ReadToEndAsync();

        // read queryString to dictionary
        var queryDictionary = HttpUtility.ParseQueryString(queryString);
        var externalIdToken =
            queryDictionary["credential"] ?? throw new AuthenticationException("Email is not verified.");
        var url = await grayMintAuthentication.GetSignInRedirectUrl(externalIdToken, queryDictionary["g_csrf_token"]);
        return Redirect(url.ToString());
    }

    [HttpGet("external/google/signin-url")]
    [AllowAnonymous]
    [Produces(MediaTypeNames.Application.Json)]
    public Task<string> GetGoogleSignInUrl(string csrfToken, string? nonce = null)
    {
        var uriBuilder = new UriBuilder {
            Scheme = Request.Scheme,
            Host = Request.Host.Host,
            Path = Request.Path.ToString()
        };

        if (Request.Host.Port != null)
            uriBuilder.Port = Request.Host.Port.Value;

        var redirectUrl = uriBuilder.ToString().Replace("/signin-url", "/signin-handler");
        var url = grayMintAuthentication.GetGoogleSignInUrl(csrfToken, nonce, redirectUrl).ToString();
        return Task.FromResult(url);
    }
}