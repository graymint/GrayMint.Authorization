using System.Net;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class AccessTest
{

    [TestMethod]
    public async Task Foo()
    {
        await Task.Delay(0);


    }

    [TestMethod]
    public async Task SystemAdmin_access()
    {
        using var testInit = await TestInit.Create();

        // Create an AppCreator
        await testInit.AddNewBot(Roles.SystemAdmin);

        // -------
        // Check: accept All apps permission
        // -------
        await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString());

        // -------
        // Check: refuse if caller does not have all app permission
        // -------
        try
        {
            await testInit.AddNewBot(Roles.AppOwner);
            await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString());
            Assert.Fail("Forbidden Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }
    }


    [TestMethod]
    public async Task SystemUser_access_by_role()
    {
        using var testInit = await TestInit.Create();

        // Create an AppCreator
        // **** Check: accept create item by AllApps access
        await testInit.AddNewBot(Roles.SystemAdmin);
        var item = await testInit.ItemsClient.CreateByRoleAsync(testInit.App.AppId, Guid.NewGuid().ToString());

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
        await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString());

        // **** Check: accept create item by the App permission
        await testInit1.AddNewBot(Roles.AppWriter);
        await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString());

        // **** Check: refuse if caller belong to other app and does not have all the app permission
        try
        {
            testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppWriter));
            await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString());
            Assert.Fail("Forbidden Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }

        // **** Check: refuse if caller does not have write permission
        try
        {
            testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppReader));
            await testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString());
            Assert.Fail("Forbidden Exception was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }

    }
}