using GrayMint.Authorization.Test.MicroServiceTest.Helper;
using GrayMint.Common.Utils;
using System.Net;

namespace GrayMint.Authorization.Test.MicroServiceTest.Tests;

[TestClass]
public class ItemAccessTest
{

    [TestMethod]
    public async Task Create_app_by_system()
    {
        using var testInit = await TestInit.Create();
        await testInit.AppsClient.CreateAppAsync();
    }

    [TestMethod]
    public async Task Create_an_item_by_App_writer()
    {
        using var testInit = await TestInit.Create();
        var apiKey = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString());
        testInit.SetApiKey(apiKey);
        var item = await testInit.ItemsClient.CreateAsync(testInit.AppId);
        await testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId);
    }

    [TestMethod]
    public async Task Fail_create_an_item_by_wrong_App_writer()
    {
        using var testInit = await TestInit.Create();
        using var testInit2 = await TestInit.Create();

        var apiKey1 = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString());
        var apiKey2 = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit2.AppId.ToString());
        testInit.SetApiKey(apiKey1);
        var item = await testInit.ItemsClient.CreateAsync(testInit.AppId);
        await testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId);

        // try with an app write belong to other app
        testInit.SetApiKey(apiKey2);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId));

    }
}

