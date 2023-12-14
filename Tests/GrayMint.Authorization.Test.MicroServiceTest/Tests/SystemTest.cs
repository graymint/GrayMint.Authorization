using System.Net;
using GrayMint.Authorization.Test.MicroServiceTest.Helper;
using GrayMint.Common.Utils;

namespace GrayMint.Authorization.Test.MicroServiceTest.Tests;

[TestClass]
public class SystemTest
{
    [TestMethod]
    public async Task Create_app_by_system()
    {
        using var testInit = await TestInit.Create();
        await testInit.AppsClient.CreateAppAsync();
    }

    [TestMethod]
    public async Task Fail_CreateApp_by_non_system_user()
    {
        using var testInit = await TestInit.Create();
        var apiKey = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString());
        testInit.SetApiKey(apiKey);

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, testInit.AppsClient.CreateAppAsync());
    }

    [TestMethod]
    public async Task Fail_ResetUserAuthorization_by_non_system_user()
    {
        using var testInit = await TestInit.Create();
        var apiKey = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString());
        testInit.SetApiKey(apiKey);

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString()));
    }
}