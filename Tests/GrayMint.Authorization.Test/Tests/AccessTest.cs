using System.Net;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Utils;
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

        // Check: accept All apps permission
        await testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString());

        // Check: 
        await testInit.AddNewBot(Roles.AppOwner);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.AppsClient.CreateAppAsync(Guid.NewGuid().ToString()),
            "refuse if caller does not have all app permission");
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

        // Check:
        testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppWriter));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString()),
            "refuse if caller belong to other app and does not have all the app permission.");

        // **** Check:
        testInit1.SetApiKey(await testInit2.AddNewBot(Roles.AppReader));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, 
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString()),
            "refuse if caller does not have write permission.");
    }

    [TestMethod]
    public async Task AppUser_access_by_hierarchy_permission()
    {
        var testInit1 = await TestInit.Create();
        var testInit2 = await TestInit.Create();
        var testInit3 = await TestInit.Create();

        // -------------
        // Check: Failed if there is no hierarchy 
        // -------------
        testInit3.SetApiKey(await testInit1.AddNewBot(Roles.AppWriter));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, 
            testInit3.ItemsClient.CreateByPermissionAsync(testInit3.App.AppId, Guid.NewGuid().ToString()));

        // Set hierarchy
        await testInit1.ResourceProvider.Update(new Resource { ResourceId = testInit2.AppId.ToString(), ParentResourceId = testInit1.AppId.ToString() });
        await testInit1.ResourceProvider.Update(new Resource { ResourceId = testInit3.AppId.ToString(), ParentResourceId = testInit2.AppId.ToString() });

        // **** Check: accept create item by Create Permission
        testInit3.SetApiKey(await testInit1.AddNewBot(Roles.SystemAdmin));
        await testInit3.ItemsClient.CreateByPermissionAsync(testInit3.App.AppId, Guid.NewGuid().ToString());

        // **** Check: accept create item by the App permission
        testInit3.SetApiKey(await testInit1.AddNewBot(Roles.AppWriter));
        await testInit3.ItemsClient.CreateByPermissionAsync(testInit3.App.AppId, Guid.NewGuid().ToString());

        // **** Check:
        testInit3.SetApiKey(await testInit2.AddNewBot(Roles.AppWriter));
        await testInit3.ItemsClient.CreateByPermissionAsync(testInit3.App.AppId, Guid.NewGuid().ToString());

        // **** Check: 
        testInit1.SetApiKey(await testInit3.AddNewBot(Roles.AppWriter));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, 
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString()),
            "refuse if caller has lower level permission.");

        // **** Check:
        testInit3.SetApiKey(await testInit1.AddNewBot(Roles.AppReader));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden, 
            testInit1.ItemsClient.CreateByPermissionAsync(testInit1.App.AppId, Guid.NewGuid().ToString()),
            "refuse if caller does not have write permission.");


    }
}