using System.Net;
using GrayMint.Authorization.Test.MicroServiceTest.Helper;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;

namespace GrayMint.Authorization.Test.MicroServiceTest.Tests;

[TestClass]
public class ItemAccessTest(TestContext testContext)
{
    private CancellationToken CancellationToken => testContext.CancellationToken;

    [TestMethod]
    public async Task Create_an_item_by_App_writer()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var apiKey = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString(), CancellationToken);
        testInit.SetApiKey(apiKey);
        var item = await testInit.ItemsClient.CreateAsync(testInit.AppId, cancellationToken: CancellationToken);
        await testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId, CancellationToken);
    }

    [TestMethod]
    public async Task Fail_unauthenticated()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        testInit.SetApiKey(new ApiKey {
            AccessToken = new Token {
                Scheme = "Bearer",
                Value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
        });

        await TestUtil.AssertApiException(
            HttpStatusCode.Unauthorized,
            testInit.ItemsClient.CreateAsync(testInit.AppId, cancellationToken: CancellationToken));
    }


    [TestMethod]
    public async Task Fail_create_an_item_by_wrong_App_writer()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // a second app in the same host, so its writer key is valid but belongs to the wrong app
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);

        var apiKey1 = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString(), CancellationToken);
        var apiKey2 = await testInit.AuthorizationClient.ResetUserApiKeyAsync(app2.AppId.ToString(), CancellationToken);
        testInit.SetApiKey(apiKey1);
        var item = await testInit.ItemsClient.CreateAsync(testInit.AppId, cancellationToken: CancellationToken);
        await testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId, CancellationToken);

        // try with an app write belong to other app
        testInit.SetApiKey(apiKey2);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId, CancellationToken));
    }

    [TestMethod]
    public async Task Fail_after_user_resetting_its_key()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        var apiKey = await testInit.AuthorizationClient.ResetUserApiKeyAsync(testInit.AppId.ToString(), CancellationToken);
        testInit.SetApiKey(apiKey);
        var item = await testInit.ItemsClient.CreateAsync(testInit.AppId, cancellationToken: CancellationToken);
        await testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId, CancellationToken);
        await testInit.AuthorizationClient.ResetCurrentUserApiKeyAsync(CancellationToken);

        // try with an app write belong to other app
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.ItemsClient.GetAsync(testInit.AppId, item.ItemId, CancellationToken));
    }
}