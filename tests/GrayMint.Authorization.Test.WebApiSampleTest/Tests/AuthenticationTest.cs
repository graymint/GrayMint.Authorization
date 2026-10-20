using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Utils;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.ApiClients;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using TokenUse = GrayMint.Authorization.Authentications.Dtos.TokenUse;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class AuthenticationTest
{
    [TestMethod]
    public async Task Foo()
    {
        await Task.Delay(1000);
        await Task.Delay(1000);
    }

    [TestMethod]
    public async Task LockUser()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.AddNewBot(Roles.AppWriter);

        // make sure the current token is working
        await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId);

        var userProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        await userProvider.Update(apiKey.UserId, new UserUpdateRequest { IsDisabled = true });

        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId),
            "make sure the current token is not working anymore");
    }

    [TestMethod]
    public async Task ResetAuthUserToken()
    {
        var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.SystemAdmin);
        var apiKey = await testInit.AuthenticationClient.ResetCurrentUserApiKeyAsync();

        // call api buy retrieved token
        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });

        //reset token
        await testInit.AuthenticationClient.ResetCurrentUserApiKeyAsync();
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }));
    }

    [TestMethod]
    public async Task ResetSystemBotAuthToken()
    {
        var testInit = await TestInit.Create();
        var user = await testInit.AddNewBot(Roles.SystemAdmin);

        // call api buy retrieved token
        var apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(user.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(user.UserId);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }));
    }

    [TestMethod]
    public async Task ResetAppBotAuthToken()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.AddNewBot(Roles.AppAdmin, false);
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: apiKey.UserId);
        var userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.IsNull(userRole.User.AccessedTime, "Newly created bot should not have AccessTime before login.");

        // call api buy retrieved token
        apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(apiKey.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId);

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(apiKey.UserId);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId));
    }

    [TestMethod]
    public async Task ResetBotAuthToken_should_not_work_for_user()
    {
        using var testInit = await TestInit.Create();
        var userRole = await testInit.AddNewUser(Roles.SystemAdmin);
        Assert.IsNotNull(userRole.User);
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.ResetBotApiKeyAsync(userRole.User.UserId));
    }

    [TestMethod]
    public async Task SignUp()
    {
        var testInit = await TestInit.Create();
        var userEmail = TestInit.NewEmail();

        // ------------
        // Check: 
        // ------------
        var idToken = await testInit.CreateUnregisteredUserIdToken(userEmail);
        testInit.HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", idToken);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.GetCurrentUserAsync(),
            "New user should not exist if not he hasn't registered yet");

        // ------------
        // Check: Register current user
        // ------------
        var apiKey = await testInit.AuthenticationClient.SignUpAsync(new SignUpRequest { IdToken = idToken });
        testInit.SetApiKey(apiKey);

        var user = await testInit.AuthenticationClient.GetCurrentUserAsync();
        Assert.AreEqual(userEmail, user.Email);

        // Get App Get
        var apps = await testInit.TeamClient.ListCurrentUserResourcesAsync();
        Assert.HasCount(0, apps);
    }

    [TestMethod]
    public async Task SignUp_with_unverified_email_creates_no_user()
    {
        using var testInit = await TestInit.Create();
        var userEmail = TestInit.NewEmail();

        // an unverified email can not sign up
        var idToken = await testInit.CreateUnregisteredUserIdToken(userEmail, isEmailVerified: false);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.SignUpAsync(new SignUpRequest { IdToken = idToken }));

        // nor did it leave a user that holds the email: it signs up once verified
        await testInit.SignUpNewUser(userEmail);
        var user = await testInit.AuthenticationClient.GetCurrentUserAsync();
        Assert.AreEqual(userEmail, user.Email);
    }

    [TestMethod]
    public async Task RefreshToken_should_extend_expiration()
    {
        var testInit = await TestInit.Create();
        var apiKey1 = await testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.Web);
        Assert.IsNotNull(apiKey1.RefreshToken);

        testInit.SetApiKey(apiKey1);
        await Task.Delay(1000);

        var apiKey2 = await testInit.AuthenticationClient.RefreshTokenAsync(
            new RefreshTokenRequest { RefreshToken = apiKey1.RefreshToken.Value });

        Assert.IsNotNull(apiKey2.RefreshToken);
        testInit.SetApiKey(apiKey2);
        await Task.Delay(1000);

        var apiKey3 = await testInit.AuthenticationClient.RefreshTokenAsync(
            new RefreshTokenRequest { RefreshToken = apiKey2.RefreshToken.Value });

        testInit.SetApiKey(apiKey3);

        Assert.IsTrue(apiKey1.AccessToken.ExpirationTime < apiKey2.AccessToken.ExpirationTime);
        Assert.IsTrue(apiKey2.AccessToken.ExpirationTime < apiKey3.AccessToken.ExpirationTime);
        Assert.IsTrue(apiKey1.RefreshToken?.ExpirationTime < apiKey2.RefreshToken?.ExpirationTime);
        Assert.IsTrue(apiKey2.RefreshToken?.ExpirationTime < apiKey3.RefreshToken?.ExpirationTime);
    }

    [TestMethod]
    public async Task Fail_refresh_a_token_more_than_long_expiration()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?> {
            { "Auth:SessionWebTimeout", "00:00:02" }
        });

        var apiKey = await testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.Web);
        Assert.IsNotNull(apiKey.RefreshToken);

        // should not extend more than long expiration
        var isAnySuccess = false;
        try {
            for (var i = 0; i < 5; i++) {
                await Task.Delay(1000);
                apiKey = await testInit.AuthenticationClient.RefreshTokenAsync(
                    new RefreshTokenRequest { RefreshToken = apiKey.RefreshToken.Value });

                Assert.IsNotNull(apiKey.RefreshToken);
                testInit.SetApiKey(apiKey);
                isAnySuccess = true;
            }

            Assert.Fail("Unauthorized Exception was expected.");
        }
        catch (ApiException ex) {
            Assert.IsTrue(isAnySuccess);
            Assert.AreEqual((int)HttpStatusCode.Unauthorized, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task RefreshToken_with_short_expiration()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?> {
            { "Auth:RefreshTokenWebTimeout", "00:01:00" },
            { "Auth:RefreshTokenAppTimeout", "00:10:00" }
        });

        var apiKey = await testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.Web);
        Assert.IsNotNull(apiKey.RefreshToken);
        Assert.IsTrue(apiKey.RefreshToken.ExpirationTime <= DateTime.UtcNow.AddMinutes(2));

        apiKey = await testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
            { RefreshToken = apiKey.RefreshToken.Value });
        Assert.IsNotNull(apiKey.RefreshToken);
        Assert.IsTrue(apiKey.RefreshToken.ExpirationTime <= DateTime.UtcNow.AddMinutes(2));
    }

    [TestMethod]
    public async Task RefreshToken_with_long_expiration()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?> {
            { "Auth:RefreshTokenWebTimeout", "00:01:00" },
            { "Auth:RefreshTokenAppTimeout", "00:10:00" }
        });

        var apiKey = await testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.App);
        Assert.IsNotNull(apiKey.RefreshToken);
        Assert.IsTrue(apiKey.RefreshToken.ExpirationTime > DateTime.UtcNow.AddMinutes(5) &&
                      apiKey.RefreshToken.ExpirationTime < DateTime.UtcNow.AddMinutes(10));

        apiKey = await testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
            { RefreshToken = apiKey.RefreshToken.Value });
        Assert.IsNotNull(apiKey.RefreshToken);
        Assert.IsTrue(apiKey.RefreshToken.ExpirationTime > DateTime.UtcNow.AddMinutes(5) &&
                      apiKey.RefreshToken.ExpirationTime < DateTime.UtcNow.AddMinutes(10));
    }

    [TestMethod]
    public async Task Fail_generate_refresh_token_if_disabled_in_settings()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?> {
            { "Auth:AllowRefreshToken", "false" },
            { "Auth:RefreshTokenAppTimeout", "00:10:00" }
        });

        await TestUtil.AssertApiException<UnauthorizedAccessException>(
            testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.App));
    }

    [TestMethod]
    public async Task Fail_sign_in_by_refresh_token()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.SignUpNewUser();

        testInit.HttpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", apiKey.RefreshToken?.Value);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.GetCurrentUserAsync(),
            "Refresh token should not be used for sign in.");
    }

    [TestMethod]
    public async Task Fail_refresh_by_access_token()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.SignUpNewUser();
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
                { RefreshToken = apiKey.AccessToken.Value }),
            "Access token should not be used as refresh_token.");
    }

    [TestMethod]
    public async Task Fail_refresh_by_id_token()
    {
        var testInit = await TestInit.Create();
        var idToken = await testInit.CreateUnregisteredUserIdToken();
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest { RefreshToken = idToken }),
            "Id token should not be used as refresh_token.");
    }


    [TestMethod]
    public async Task Fail_refresh_a_revoked_token()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.SignUpNewUser(refreshTokenType: RefreshTokenType.Web);
        Assert.IsNotNull(apiKey.RefreshToken);

        await testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
            { RefreshToken = apiKey.RefreshToken.Value });
        await testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
            { RefreshToken = apiKey.RefreshToken.Value });
        await testInit.AuthenticationClient.ResetCurrentUserApiKeyAsync();
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.RefreshTokenAsync(new RefreshTokenRequest
                { RefreshToken = apiKey.RefreshToken.Value }),
            "Revoked token should not be refreshed.");
    }

    [TestMethod]
    public async Task Token_without_auth_code_is_refused()
    {
        using var testInit = await TestInit.Create();
        var bot = await testInit.AddNewBot(Roles.AppReader);
        await testInit.TeamClient.ListCurrentUserResourcesAsync();

        // the same bot's token, signed with the server's own key but carrying no auth code
        var options = testInit.AuthenticationOptions;
        var token = JwtUtil.CreateSymmetricJwt(options.Secret, options.Issuer, options.Audience ?? options.Issuer,
            subject: bot.UserId,
            claims: [
                new Claim(GrayMintClaimTypes.TokenUse, TokenUse.Access),
                new Claim(GrayMintClaimTypes.Version, "2", ClaimValueTypes.Integer)
            ],
            expirationTime: DateTime.UtcNow.AddHours(1));
        testInit.HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.TeamClient.ListCurrentUserResourcesAsync());
    }

    [TestMethod]
    public async Task Extra_audiences_are_accepted_but_never_issued()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { ["Auth:Audiences:0"] = "old-audience" });
        var apiKey = await testInit.SignUpNewUser();
        var user = await testInit.UserProvider.Get(apiKey.UserId);
        var options = testInit.AuthenticationOptions;

        // our own tokens carry the main audience only
        var issuedToken = new JwtSecurityTokenHandler().ReadJwtToken(apiKey.AccessToken.Value);
        Assert.AreEqual(options.Audience ?? options.Issuer, issuedToken.Audiences.Single());

        // a token for the extra audience works, any other audience doesn't
        foreach (var audience in new[] { "old-audience", "other-audience" }) {
            var token = JwtUtil.CreateSymmetricJwt(options.Secret, options.Issuer, audience,
                subject: apiKey.UserId,
                claims: [
                    new Claim(GrayMintClaimTypes.TokenUse, TokenUse.Access),
                    new Claim(GrayMintClaimTypes.Version, "2", ClaimValueTypes.Integer),
                    new Claim(GrayMintClaimTypes.AuthCode, user.AuthorizationCode ?? string.Empty)
                ],
                expirationTime: DateTime.UtcNow.AddHours(1));
            testInit.HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            if (audience == "old-audience")
                await testInit.TeamClient.ListCurrentUserResourcesAsync();
            else
                await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
                    testInit.TeamClient.ListCurrentUserResourcesAsync());
        }
    }

    [TestMethod]
    public async Task Sign_in_keeps_only_profile_claims()
    {
        using var testInit = await TestInit.Create();

        // an id token that also carries a permission and a role
        var permissionClaim = PermissionAuthorization.BuildPermissionClaim(testInit.AppResourceId, Permissions.CustomerRead);
        var apiKey = await testInit.SignUpNewUser(claims: [
            permissionClaim,
            new Claim(ClaimTypes.Role, Roles.SystemAdmin.RoleName),
            new Claim(ClaimTypes.GivenName, "Ada")
        ]);

        var accessToken = new JwtSecurityTokenHandler().ReadJwtToken(apiKey.AccessToken.Value);
        Assert.IsFalse(accessToken.Claims.Any(x => x.Type == permissionClaim.Type));
        Assert.IsFalse(accessToken.Claims.Any(x => x.Type is "role" or ClaimTypes.Role));
        Assert.IsTrue(accessToken.Claims.Any(x => x.Value == "Ada"));
    }

    [TestMethod]
    public async Task Current_user_answer_hides_the_auth_code()
    {
        using var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.AppReader);
        var user = await testInit.AuthenticationClient.GetCurrentUserAsync();
        Assert.IsNull(user.AuthorizationCode);
    }

    [TestMethod]
    public async Task System_api_key_is_off_when_disabled()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { ["Auth:AllowSystemApiKey"] = "false" },
            createSystemAdmin: false);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.CreateSystemApiKeyAsync(Convert.ToBase64String(testInit.AuthenticationOptions.Secret)));
    }

    [TestMethod]
    public async Task System_api_key_refuses_a_secret_that_is_no_base64()
    {
        using var testInit = await TestInit.Create();
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.CreateSystemApiKeyAsync("not base64!"));
    }

    [TestMethod]
    public void System_api_key_is_off_in_production_unless_set()
    {
        var options = new GrayMintAuthenticationOptions { Secret = [1], Issuer = "local" };
        Assert.IsFalse(options.IsSystemApiKeyAllowed(isProduction: true));
        Assert.IsTrue(options.IsSystemApiKeyAllowed(isProduction: false));

        options = new GrayMintAuthenticationOptions { Secret = [1], Issuer = "local", AllowSystemApiKey = true };
        Assert.IsTrue(options.IsSystemApiKeyAllowed(isProduction: true));
    }
}