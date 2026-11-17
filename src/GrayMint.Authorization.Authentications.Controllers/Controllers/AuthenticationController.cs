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

/// <summary>
/// Signing in, and the signed-in user's own account.
/// </summary>
/// <remarks>
/// An ID token from one of the service's identity providers is exchanged here for an API key: an access token, sent as
/// `Authorization: Bearer &lt;token&gt;` with every other request, and, if asked for, a refresh token that gets a new
/// one when it expires.
/// </remarks>
// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Authorize]
[Route("/api/authentication")]
public class AuthenticationController(
    AuthenticationService authenticationService,
    GrayMintAuthentication grayMintAuthentication)
    : ControllerBase
{
    /// <summary>
    /// Get the signed-in user
    /// </summary>
    /// <remarks>
    /// The person or bot the request's access token belongs to. The fields the service keeps for itself are empty.
    /// </remarks>
    /// <returns>The signed-in user.</returns>
    [HttpGet("current")]
    [Authorize]
    public virtual async Task<User> GetCurrentUser()
    {
        var userId = await authenticationService.GetUserId(User);
        var ret = await authenticationService.GetUser(userId);
        return ret;
    }

    /// <summary>
    /// Sign out everywhere
    /// </summary>
    /// <remarks>
    /// Every access and refresh token of the signed-in user stops working, the one of this request too.
    /// </remarks>
    [HttpPost("current/signout-all")]
    [Authorize]
    public virtual async Task SignOutAll()
    {
        var userId = await authenticationService.GetUserId(User);
        await authenticationService.ResetAuthorizationCode(userId);
    }

    /// <summary>
    /// Get a new API key for yourself
    /// </summary>
    /// <remarks>
    /// A long-lived access token without a refresh token, for a script that acts as you. Every earlier token of yours
    /// stops working. The service may not allow users API keys of their own.
    /// </remarks>
    /// <returns>The new API key, shown only here.</returns>
    [HttpPost("current/reset-api-key")]
    [Authorize]
    public virtual async Task<ApiKey> ResetCurrentUserApiKey()
    {
        var userId = await authenticationService.GetUserId(User);
        var res = await authenticationService.ResetApiKey(userId);
        return res;
    }

    /// <summary>
    /// Sign in with an ID token
    /// </summary>
    /// <remarks>
    /// The ID token comes from one of the service's identity providers, with a verified email, and its account must
    /// exist already: a new user signs up instead. The account's name and picture follow the token's.
    /// </remarks>
    /// <param name="request">The ID token, and which refresh token to get with the access token.</param>
    /// <returns>The API key.</returns>
    [HttpPost("signin")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> SignIn(SignInRequest request)
    {
        var apiKey = await authenticationService.SignIn(request);
        return apiKey;
    }

    /// <summary>
    /// Create an account with an ID token, and sign in
    /// </summary>
    /// <remarks>
    /// The account takes the token's verified email, name and picture. The service may not let people sign up
    /// themselves.
    /// </remarks>
    /// <param name="request">The ID token, and which refresh token to get with the access token.</param>
    /// <returns>The API key.</returns>
    [HttpPost("signup")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> SignUp(SignUpRequest request)
    {
        var apiKey = await authenticationService.SignUp(request);
        return apiKey;
    }

    /// <summary>
    /// Get a new access token with a refresh token
    /// </summary>
    /// <remarks>
    /// A refresh token works until it expires and its session ends, both set by its type, or until the user signs out
    /// everywhere.
    /// </remarks>
    /// <param name="request">The refresh token.</param>
    /// <returns>A new API key.</returns>
    [HttpPost("refresh-token")]
    [AllowAnonymous]
    public virtual async Task<ApiKey> RefreshToken(RefreshTokenRequest request)
    {
        var apiKey = await grayMintAuthentication.RefreshToken(request.RefreshToken);
        return apiKey;
    }

    /// <summary>
    /// Finish a sign-in with Google
    /// </summary>
    /// <remarks>
    /// Google's sign-in page sends the browser here with a form of its ID token (`credential`) and `g_csrf_token`.
    /// The browser goes on to the service's sign-in page with an ID token of the service's own (`id_token`) and the
    /// CSRF token (`csrf_token`), to sign in with.
    /// </remarks>
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

    /// <summary>
    /// Get the address of Google's sign-in page
    /// </summary>
    /// <remarks>
    /// After it, Google sends the browser to this service's `external/google/signin-handler`.
    /// </remarks>
    /// <param name="csrfToken">A random value that comes back with the sign-in, to show the caller started it.</param>
    /// <param name="nonce">A value Google puts in its ID token, which ties the token to this sign-in.</param>
    /// <returns>The address to send the browser to.</returns>
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