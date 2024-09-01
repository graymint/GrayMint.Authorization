using System.Net;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class ItemAccessTest
{

    [TestMethod]
    public Task Foo()
    {
        return Task.Delay(0);
    }

    [TestMethod]
    public async Task SystemAdmin_access()
    {
        using var testInit = await TestInit.Create();

        // Create an AppCreator
        await testInit.AddNewBot(Roles.SystemAdmin);

        // Check: accept All apps permission
        await testInit.AppsClient.CreateAppAsync();

        // Check: 
        await testInit.AddNewBot(Roles.AppOwner);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.AppsClient.CreateAppAsync(),
            "refuse if caller does not have all app permission");
    }


    [TestMethod]
    public async Task SystemUser_access_by_role()
    {
        using var testInit = await TestInit.Create();

        // Create an AppCreator
        // **** Check: accept create item by AllApps access
        await testInit.AddNewBot(Roles.SystemAdmin);
        var item = await testInit.ItemsClient.CreateByRoleAsync(testInit.App.AppId);

        // **** Check: accept get item by AllApps access
        await testInit.AddNewBot(Roles.SystemReader);
        await testInit.ItemsClient.GetByRoleAsync(testInit.App.AppId, item.ItemId);
    }

    [TestMethod]
    public async Task AppUser_access_by_permission()
    {
        var testInit1 = await TestInit.Create();
        var testInit2 = await TestInit.Create();
        // Create an AppCreator

        // **** Check: accept create item by Create Permission
        await testInit1.AddNewBot(Roles.SystemAdmin);
        await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId);

        // **** Check: accept create item by the App permission
        await testInit1.AddNewBot(Roles.AppWriter);
        await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId);

        // Check:
        testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppWriter));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId),
            "refuse if caller belong to other app and does not have all the app permission.");

        // **** Check:
        testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppReader));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, 
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId),
            "refuse if caller does not have write permission.");
    }
}