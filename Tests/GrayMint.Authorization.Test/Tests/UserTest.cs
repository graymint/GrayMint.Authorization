using System.Net;
using GrayMint.Authorization.RoleManagement.TeamControllers.Exceptions;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class UserTest
{
    [TestMethod]
    public async Task ResetAuthUserToken()
    {
        var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.SystemAdmin);
        var apiKey = await testInit.TeamClient.ResetCurrentUserApiKeyAsync();

        // call api buy retrieved token
        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString()); // make sure the current token is working

        //reset token
        await testInit.TeamClient.ResetCurrentUserApiKeyAsync();
        await Task.Delay(200);
        try
        {
            await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString());
            Assert.Fail("Unauthorized Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Unauthorized, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task ResetSystemBotAuthToken()
    {
        var testInit = await TestInit.Create();
        var user = await testInit.AddNewBot(Roles.SystemAdmin);

        // call api buy retrieved token
        var apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(user.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString()); // make sure the current token is working

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(user.UserId);
        await Task.Delay(200);
        try
        {
            await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString());
            Assert.Fail("Unauthorized Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Unauthorized, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task ResetAppBotAuthToken()
    {
        var testInit = await TestInit.Create();
        var apiKey = await testInit.AddNewBot(Roles.AppAdmin, false);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: apiKey.UserId);
        var userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.IsNull(userRole.User.AccessedTime, "Newly created bot should not have AccessTime before login.");

        // call api buy retrieved token
        apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(apiKey.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId, Guid.NewGuid().ToString()); // make sure the current token is working

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(apiKey.UserId);
        await Task.Delay(200);
        try
        {
            await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId, Guid.NewGuid().ToString()); // make sure the current token is working
            Assert.Fail("Unauthorized Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Unauthorized, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task ResetSystemBotAuthToken_should_not_work_for_user()
    {
        using var testInit = await TestInit.Create();

        var userRole = await testInit.AddNewUser(Roles.SystemAdmin);
        Assert.IsNotNull(userRole.User);

        try
        {
            await testInit.TeamClient.ResetBotApiKeyAsync(userRole.User.UserId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    [TestMethod]
    public async Task ResetAppBotAuthToken_should_not_work_for_user()
    {
        using var testInit = await TestInit.Create();

        var userRole = await testInit.AddNewUser(Roles.SystemAdmin);
        Assert.IsNotNull(userRole.User);

        try
        {
            await testInit.TeamClient.ResetBotApiKeyAsync(userRole.User.UserId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    [TestMethod]
    public async Task SignUp()
    {
        var testInit = await TestInit.Create();
        var userEmail = TestInit.NewEmail();

        // ------------
        // Check: New user should not exist if not he hasn't registered yet
        // ------------
        await testInit.CreateUnregisteredUser(userEmail);

        try
        {
            await testInit.TeamClient.GetCurrentUserAsync();
            Assert.Fail("User should not exist!");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(UnregisteredUser), ex.ExceptionTypeName);
        }

        // ------------
        // Check: Register current user
        // ------------
        var apiKey = await testInit.TeamClient.SignUpAsync();
        testInit.SetApiKey(apiKey);

        var user = await testInit.TeamClient.GetCurrentUserAsync();
        Assert.AreEqual(userEmail, user.Email);

        // Get App Get
        var apps = await testInit.TeamClient.ListCurrentUserResourcesAsync();
        Assert.AreEqual(0, apps.Count);
    }

    [TestMethod]
    public async Task SignIn_should_extend_expiration()
    {
        var testInit = await TestInit.Create();

        await testInit.CreateUnregisteredUser();
        var apiKey1 = await testInit.TeamClient.SignUpAsync();
        testInit.SetApiKey(apiKey1);
        await Task.Delay(1000);

        var apiKey2 = await testInit.TeamClient.SignInAsync();
        testInit.SetApiKey(apiKey2);
        await Task.Delay(1000);

        var apiKey3 = await testInit.TeamClient.SignInAsync();
        testInit.SetApiKey(apiKey3);

        Assert.IsTrue(apiKey1.Expiration < apiKey2.Expiration);
        Assert.IsTrue(apiKey2.Expiration < apiKey3.Expiration);

    }

    [TestMethod]
    public async Task SignIn_should_not_extend_more_than_long_expiration()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?>
        {
            {"TeamController:UserTokenLongExpiration", "00:00:02" }
        });

        await testInit.CreateUnregisteredUser();
        var apiKey = await testInit.TeamClient.SignUpAsync();
        testInit.SetApiKey(apiKey);

        // should not extend more than long expiration
        try
        {
            for (var i = 0; i < 5; i++)
            {
                await Task.Delay(1000);
                apiKey = await testInit.TeamClient.SignInAsync();
                testInit.SetApiKey(apiKey);
            }
            Assert.Fail("Unauthorized Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Unauthorized, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task SignIn_using_short_and_long_expiration()
    {
        var testInit = await TestInit.Create(new Dictionary<string, string?>
        {
            {"TeamController:UserTokenShortExpiration", "00:01:00" },
            {"TeamController:UserTokenLongExpiration", "00:10:00" }
        });

        await testInit.CreateUnregisteredUser();
        var apiKey = await testInit.TeamClient.SignUpAsync();
        testInit.SetApiKey(apiKey);
        Assert.IsTrue(apiKey.Expiration <= DateTime.UtcNow.AddMinutes(1));

        apiKey = await testInit.TeamClient.SignInAsync();
        testInit.SetApiKey(apiKey);
        Assert.IsTrue(apiKey.Expiration <= DateTime.UtcNow.AddMinutes(1));

        apiKey = await testInit.TeamClient.SignInAsync(true);
        testInit.SetApiKey(apiKey);
        Assert.IsTrue(apiKey.Expiration > DateTime.UtcNow.AddMinutes(1) && apiKey.Expiration < DateTime.UtcNow.AddMinutes(10));
    }
}