using System.Net;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class ResourceProviderTest : TestBase
{
    [TestMethod]
    public async Task AppUser_access_by_hierarchy_permission()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var app1 = testInit.App.AppId;
        var createdApp2 = await testInit.AppsClient.CreateAppAsync();
        var createdApp3 = await testInit.AppsClient.CreateAppAsync();
        var app2 = createdApp2.AppId;
        var app3 = createdApp3.AppId;

        // set app parent resource 
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app1.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app2.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app3.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        // -------------
        // Check: Failed if there is no hierarchy 
        // -------------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app1));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app3));

        // Set hierarchy
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app2.ToString(), ParentResourceId = app1.ToString() });

        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app3.ToString(), ParentResourceId = app2.ToString() });

        // -------------
        // **** Check: accept create item by System Admin
        // -------------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.SystemAdmin));
        await testInit.ItemsClient.CreateByPermissionAsync(app3);

        // -------------
        // **** Check: accept create item by the App Writer on app1
        // -------------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app1));
        await testInit.ItemsClient.CreateByPermissionAsync(app3);

        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app2));
        await testInit.ItemsClient.CreateByPermissionAsync(app3);

        // -----------
        // **** Check: Refuse if caller has lower level permission
        // -----------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app3));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app1));

        // -----------
        // **** Check: "refuse if caller does not have write permission even if it is on higher level."
        // -----------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppReader, resourceId: app1));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app3));
    }

    [TestMethod]
    public async Task AppUser_access_by_hierarchy_permission_after_update()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var app1 = testInit.App;
        var app2 = await testInit.AppsClient.CreateAppAsync();
        var app3 = await testInit.AppsClient.CreateAppAsync();
        var app4 = await testInit.AppsClient.CreateAppAsync();
        var app5 = await testInit.AppsClient.CreateAppAsync();

        // set app parent resource 
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app1.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app2.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app3.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app4.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        await testInit.ResourceProvider.Add(new Resource
            { ResourceId = app5.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        // -----------
        // **** Check:  Should not have access if user have not access on its parent or itself.
        // -----------

        // create a user that has access to app4
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app1.AppId));

        // Set hierarchy
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app2.AppId.ToString(), ParentResourceId = app1.AppId.ToString() });

        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app3.AppId.ToString(), ParentResourceId = app2.AppId.ToString() });

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app4.AppId));

        // -----------
        // **** Check: Should have access if it is one of its parent.
        // -----------
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app4.AppId.ToString(), ParentResourceId = app3.AppId.ToString() });

        await testInit.ItemsClient.CreateByPermissionAsync(app4.AppId);

        // -----------
        // **** Check: Should not have access if it is not one of its parent after moving a node in the middle
        // -----------
        await testInit.ResourceProvider.Update(new Resource
            { ResourceId = app2.AppId.ToString(), ParentResourceId = app5.AppId.ToString() });

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app4.AppId));
    }

    [TestMethod]
    public async Task Root_must_exists()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var resource = await testInit.ResourceProvider.Get(testInit.ResourceProvider.RootResourceId);
        Assert.IsNull(resource.ParentResourceId);
    }

    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        // ---------
        // Check: Get
        // ---------
        resource2 = await resourceProvider.Get(resource2.ResourceId);
        Assert.AreEqual(resource1.ResourceId, resource2.ParentResourceId);

        // ---------
        // Check: Update
        // ---------
        resource2 = await resourceProvider.Update(new Resource {
            ResourceId = resource2.ResourceId,
            ParentResourceId = resource1.ParentResourceId
        });

        Assert.AreEqual(resource1.ParentResourceId, resource2.ParentResourceId);
        resource2 = await resourceProvider.Get(resource2.ResourceId);
        Assert.AreEqual(resource1.ParentResourceId, resource2.ParentResourceId);

        // ---------
        // Check: Delete
        // ---------
        await resourceProvider.Remove(resource2.ResourceId);
        await TestUtil.AssertNotExistsException(resourceProvider.Get(resource2.ResourceId));
    }

    [TestMethod]
    public async Task Fail_loop_on_create()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);

        // loop on self
        var id1 = Guid.NewGuid().ToString();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            testInit.ResourceProvider.Add(new Resource { ResourceId = id1, ParentResourceId = id1 }));
    }

    [TestMethod]
    public async Task Fail_loop_on_update()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // loop on self
        var resource = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        await Assert.ThrowsAsync<InvalidOperationException>(() => resourceProvider.Update(new Resource
            { ResourceId = resource.ResourceId, ParentResourceId = resource.ResourceId }));

        // deep loop
        var resource1 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resourceProvider.RootResourceId
        });

        var resource2 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource4 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        // loop through the children
        await Assert.ThrowsAsync<InvalidOperationException>(() => resourceProvider.Update(new Resource
            { ResourceId = resource1.ResourceId, ParentResourceId = resource4.ResourceId }));
    }

    [TestMethod]
    public async Task Delete_Recursive()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        var resource21 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource22 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });


        // ---------
        // Check: Delete
        // ---------
        await resourceProvider.Remove(resource1.ResourceId);
        await TestUtil.AssertNotExistsException(resourceProvider.Get(resource2.ResourceId));
        await TestUtil.AssertNotExistsException(resourceProvider.Get(resource21.ResourceId));
        await TestUtil.AssertNotExistsException(resourceProvider.Get(resource22.ResourceId));
    }

    [TestMethod]
    public async Task Delete_resource_must_delete_all_its_roles()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });


        // create a user
        var userProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var userCreateRequest = new UserCreateRequest {
            Email = $"{Guid.NewGuid()}@local",
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        };

        var user = await userProvider.Create(userCreateRequest);

        // assign role
        var userRoleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await userRoleProvider.AddUserRole(resource2.ResourceId, Roles.AppAdmin.RoleId, user.UserId);

        // get user roles
        var userRoles = await userRoleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.Contains(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId, userRoles);

        // delete and get user roles again
        await testInit.ResourceProvider.Remove(resource2.ResourceId);
        userRoles = await userRoleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.DoesNotContain(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId,
            userRoles);
    }

    [TestMethod]
    public async Task Fail_removing_the_root()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            testInit.ResourceProvider.Remove(testInit.ResourceProvider.RootResourceId));
    }

    [TestMethod]
    public async Task Fail_updating_root()
    {
        using var testInit = await CreateTestInit(useResourceProvider: true);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            testInit.ResourceProvider.Update(new Resource { ResourceId = testInit.ResourceProvider.RootResourceId }));
    }
}