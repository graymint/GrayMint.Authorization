using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Abstractions.Exceptions;
using GrayMint.Authorization.Authentications.Controllers.Dtos;
using GrayMint.Authorization.Authentications.Dtos;
using GrayMint.Authorization.Authentications.Utils;
using GrayMint.Authorization.UserManagement.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace GrayMint.Authorization.Authentications.Controllers.Services;

public class AuthenticationService(
    IOptions<GrayMintAuthenticationOptions> authenticationOptions,
    GrayMintAuthentication grayMintAuthentication,
    IUserProvider userProvider,
    IAuthorizationProvider authorizationProvider,
    GrayMintTokenValidator grayMintIdTokenValidator)
{
    public Uri? SignInRedirectUrl => authenticationOptions.Value.SignInRedirectUrl;

    public async Task<string> GetUserId(ClaimsPrincipal user)
    {
        var userId = await authorizationProvider.GetUserId(user) ?? throw new UnregisteredUserException();
        return userId;
    }

    public async Task<User> GetUser(string userId)
    {
        var user = await userProvider.Get(userId);

        //AccessedTime should not be set for user due security reason and sharing user account among projects,
        user.AccessedTime = null;
        return user;
    }

    public async Task<User> ResetAuthorizationCode(string userId)
    {
        var user = await userProvider.Get(userId);
        await userProvider.ResetAuthorizationCode(user.UserId);
        return user;
    }

    public async Task<ApiKey> ResetApiKey(string userId)
    {
        var user = await userProvider.Get(userId);

        // check AllowUserApiKey for user
        if (!authenticationOptions.Value.AllowUserApiKey)
            throw new UnauthorizedAccessException("User ApiKey is not enabled.");

        // reset the api key
        await userProvider.ResetAuthorizationCode(user.UserId);

        // create new api key
        var claimIdentity = new ClaimsIdentity();
        claimIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, user.UserId));
        var apiKey = await grayMintAuthentication
            .CreateApiKey(claimIdentity, new ApiKeyOptions
            {
                AccessTokenExpirationTime = JwtUtil.UtcNow.AddYears(13),
                RefreshTokenType = RefreshTokenType.None,
            });

        return apiKey;
    }

    private async Task UpdateUserByClaims(User user, ClaimsPrincipal claimsPrincipal)
    {
        var updateRequest = new UserUpdateRequest();
        var isUpdated = false;

        var email = claimsPrincipal.FindFirstValue(ClaimTypes.Email);
        if (email != null && user.Email != email) { updateRequest.Email = email; isUpdated = true; }

        var name = claimsPrincipal.FindFirstValue(ClaimTypes.Name);
        if (name != null && user.Name != name) { updateRequest.Name = name; isUpdated = true; }

        var firstName = claimsPrincipal.FindFirstValue(ClaimTypes.GivenName);
        if (firstName != null && user.FirstName != firstName) { updateRequest.FirstName = firstName; isUpdated = true; }

        var lastName = claimsPrincipal.FindFirstValue(ClaimTypes.Surname);
        if (lastName != null && user.LastName != lastName) { updateRequest.LastName = lastName; isUpdated = true; }

        var phone = claimsPrincipal.FindFirstValue(ClaimTypes.MobilePhone);
        if (phone != null && user.Name != phone) { updateRequest.Phone = phone; isUpdated = true; }

        var pictureUrl = claimsPrincipal.FindFirstValue(GrayMintClaimTypes.Picture);
        if (pictureUrl != null && user.PictureUrl != pictureUrl) { updateRequest.PictureUrl = pictureUrl; isUpdated = true; }

        var isEmailVerified = claimsPrincipal.FindFirstValue(GrayMintClaimTypes.EmailVerified);
        if (isEmailVerified != null && user.IsEmailVerified != bool.Parse(isEmailVerified)) { updateRequest.IsEmailVerified = bool.Parse(isEmailVerified); isUpdated = true; }

        if (isUpdated)
            await userProvider.Update(user.UserId, updateRequest);
    }

    public async Task<ApiKey> SignIn(SignInRequest signInRequest)
    {
        var apiKey = await grayMintAuthentication
            .SignIn(signInRequest.IdToken, signInRequest.RefreshTokenType);

        // make sure userId is not null 
        if (apiKey.UserId is null)
            throw new Exception("SignIn should not return null UserId.");

        // update user profile by claims
        if (apiKey.AccessToken.ClaimsPrincipal is not null)
        {
            var user = await userProvider.Get(apiKey.UserId);
            await UpdateUserByClaims(user, apiKey.AccessToken.ClaimsPrincipal);
        }

        return apiKey;
    }

    public async Task<ApiKey> SignUp(SignUpRequest signUpRequest)
    {
        if (!authenticationOptions.Value.AllowUserSelfRegister)
            throw new UnauthorizedAccessException("Self-Register is not enabled.");

        var claimsIdentity = await grayMintIdTokenValidator.ValidateIdToken(signUpRequest.IdToken);
        var claimsPrincipal = ClaimUtil.CreateClaimsPrincipal(claimsIdentity);

        var email =
            claimsPrincipal.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Email)?.Value.ToLower()
            ?? throw new UnauthorizedAccessException("Could not find user's email claim!");

        var user = await userProvider.Create(new UserCreateRequest { Email = email });
        await UpdateUserByClaims(user, claimsPrincipal);

        var apiKey = await grayMintAuthentication.SignIn(
            signUpRequest.IdToken, signUpRequest.RefreshTokenType);

        return apiKey;
    }
}

