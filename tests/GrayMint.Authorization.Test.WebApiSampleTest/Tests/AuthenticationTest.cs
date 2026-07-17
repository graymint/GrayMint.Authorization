using System.Net;
using System.Net.Http.Headers;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.ApiClients;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;

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
        await Task.Delay(200);
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
        await Task.Delay(200);
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
        await Task.Delay(200);
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
}