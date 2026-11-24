using System.Net;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class ItemAccessTest(TestContext testContext)
{
    private CancellationToken CancellationToken => testContext.CancellationToken;

    [TestMethod]
    public Task Foo()
    {
        return Task.Delay(0, CancellationToken);
    }

    [TestMethod]
    public async Task SystemAdmin_access()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // Create an AppCreator
        await testInit.AddNewBot(Roles.SystemAdmin);

        // Check: accept All apps permission
        await testInit.AppsClient.CreateAppAsync(cancellationToken: CancellationToken);

        // Check: 
        await testInit.AddNewBot(Roles.AppOwner);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.AppsClient.CreateAppAsync(cancellationToken: CancellationToken),
            "refuse if caller does not have all app permission");
    }


    [TestMethod]
    public async Task SystemUser_access_by_role()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // Create an AppCreator
        // **** Check: accept create item by AllApps access
        await testInit.AddNewBot(Roles.SystemAdmin);
        var item = await testInit.ItemsClient.CreateByRoleAsync(testInit.App.AppId, cancellationToken: CancellationToken);

        // **** Check: accept get item by AllApps access
        await testInit.AddNewBot(Roles.SystemReader);
        await testInit.ItemsClient.GetByRoleAsync(testInit.App.AppId, item.ItemId, CancellationToken);
    }

    [TestMethod]
    public async Task AppUser_access_by_permission()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // **** Check: accept create item by Create Permission
        await testInit.AddNewBot(Roles.SystemAdmin);
        await testInit.ItemsClient.CreateByPermissionAsync(testInit.App.AppId, cancellationToken: CancellationToken);

        // **** Check: accept create item by the App permission
        await testInit.AddNewBot(Roles.AppWriter);
        await testInit.ItemsClient.CreateByPermissionAsync(testInit.App.AppId, cancellationToken: CancellationToken);

        // a second app in the same host, so its keys are valid but belong to another app
        testInit.SetApiKey(testInit.SystemAdminApiKey);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);

        // Check:
        await testInit.AddNewBot(Roles.AppWriter, resourceId: app2.AppId);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(testInit.App.AppId, cancellationToken: CancellationToken),
            "refuse if caller belong to other app and does not have all the app permission.");

        // **** Check:
        await testInit.AddNewBot(Roles.AppReader, resourceId: app2.AppId);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(testInit.App.AppId, cancellationToken: CancellationToken),
            "refuse if caller does not have write permission.");
    }
}