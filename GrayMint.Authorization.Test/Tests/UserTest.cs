using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using GrayMint.Authorization.Authentications.BotAuthentication;
using GrayMint.Authorization.RoleManagement.RoleControllers.Exceptions;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.WebApiSample.Security;
using GrayMint.Common.Client;
using GrayMint.Common.Test.Api;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class UserTest
{
    [TestMethod]
    public async Task ResetAuthUserToken()
    {
        var testInit = await TestInit.Create();
        await testInit.AddNewUser(Roles.SystemAdmin);
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
        var user = await testInit.AddNewUser(Roles.SystemAdmin);

        // call api buy retrieved token
        var apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(0, user.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString()); // make sure the current token is working

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(0, user.UserId);
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
        var apiKey = await testInit.AddNewUser(Roles.AppAdmin, false);
        var userRole = await testInit.TeamClient.GetUserAsync(testInit.AppId, apiKey.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.IsNull(userRole.User.AccessedTime, "Newly created bot should not have AccessTime before login.");

        // call api buy retrieved token
        apiKey = await testInit.TeamClient.ResetBotApiKeyAsync(testInit.App.AppId, apiKey.UserId);
        testInit.SetApiKey(apiKey);
        await testInit.ItemsClient.CreateAsync(testInit.AppId, Guid.NewGuid().ToString()); // make sure the current token is working

        //reset token
        await testInit.TeamClient.ResetBotApiKeyAsync(testInit.AppId, apiKey.UserId);
        await Task.Delay(200);
        try
        {
            await testInit.ItemsClient.CreateAsync(testInit.AppId, Guid.NewGuid().ToString()); // make sure the current token is working
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

        var userRole = await testInit.TeamClient.AddUserAsync(0, new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.SystemAdmin.RoleId
        });
        Assert.IsNotNull(userRole.User);

        try
        {
            await testInit.TeamClient.ResetBotApiKeyAsync(0, userRole.User.UserId);
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

        var userRole = await testInit.TeamClient.AddUserAsync(testInit.AppId, new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.AppAdmin.RoleId
        });
        Assert.IsNotNull(userRole.User);

        try
        {
            await testInit.TeamClient.ResetBotApiKeyAsync(testInit.AppId, userRole.User.UserId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    private static async Task<AuthenticationHeaderValue> CreateUnregisteredUserAuthorization(IServiceScope scope, string email, Claim[]? claims = null)
    {
        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, email));
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        claimsIdentity.AddClaim(new Claim("test_authenticated", "1"));
        if (claims != null)
            claimsIdentity.AddClaims(claims);

        var authenticationTokenBuilder = scope.ServiceProvider.GetRequiredService<BotAuthenticationTokenBuilder>();
        return await authenticationTokenBuilder.CreateAuthenticationHeader(claimsIdentity);
    }

    [TestMethod]
    public async Task RegisterCurrentUser()
    {
        var testInit = await TestInit.Create();
        var userEmail = TestInit.NewEmail();

        // ------------
        // Check: New user should not exist if not he hasn't registered yet
        // ------------
        testInit.HttpClient.DefaultRequestHeaders.Authorization = await CreateUnregisteredUserAuthorization(testInit.Scope, userEmail);
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
        await testInit.TeamClient.RegisterCurrentUserAsync();
        var user = await testInit.TeamClient.GetCurrentUserAsync();
        Assert.AreEqual(userEmail, user.Email);

        // Get App Get
        var apps = await testInit.TeamClient.ListCurrentUserResourcesAsync();
        Assert.AreEqual(0, apps.Count);
    }
}