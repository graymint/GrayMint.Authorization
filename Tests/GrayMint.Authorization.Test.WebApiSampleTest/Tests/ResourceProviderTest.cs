using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class ResourceProviderTest
{
    [TestMethod]
    public async Task AppUser_access_by_hierarchy_permission()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var app1 = testInit.App.AppId;
        var app2 = (await testInit.AppsClient.CreateAppAsync()).AppId;
        var app3 = (await testInit.AppsClient.CreateAppAsync()).AppId;

        // set app parent resource 
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app1.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app2.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app3.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        // -------------
        // Check: Failed if there is no hierarchy 
        // -------------
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app1));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app3));

        // Set hierarchy
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app2.ToString(), ParentResourceId = app1.ToString() });
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app3.ToString(), ParentResourceId = app2.ToString() });

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
        var testInit = await TestInit.Create(useResourceProvider: true);
        var app1 = testInit.App;
        var app2 = await testInit.AppsClient.CreateAppAsync();
        var app3 = await testInit.AppsClient.CreateAppAsync();
        var app4 = await testInit.AppsClient.CreateAppAsync();
        var app5 = await testInit.AppsClient.CreateAppAsync();

        // set app parent resource 
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app1.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app2.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app3.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app4.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = app5.AppId.ToString(), ParentResourceId = testInit.ResourceProvider.RootResourceId });

        // -----------
        // **** Check:  Should not have access if user have not access on its parent or itself.
        // -----------
        
        // create a user that has access to app4
        testInit.SetApiKey(await testInit.AddNewBot(Roles.AppWriter, resourceId: app1.AppId));

        // Set hierarchy
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app2.AppId.ToString(), ParentResourceId = app1.AppId.ToString() });
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app3.AppId.ToString(), ParentResourceId = app2.AppId.ToString() });
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app4.AppId));

        // -----------
        // **** Check: Should have access if it is one of its parent.
        // -----------
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app4.AppId.ToString(), ParentResourceId = app3.AppId.ToString() });
        await testInit.ItemsClient.CreateByPermissionAsync(app4.AppId);

        // -----------
        // **** Check: Should not have access if it is not one of its parent after moving a node in the middle
        // -----------
        await testInit.ResourceProvider.Update(new Resource { ResourceId = app2.AppId.ToString(), ParentResourceId = app5.AppId.ToString() });
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.ItemsClient.CreateByPermissionAsync(app4.AppId));
    }

    [TestMethod]
    public async Task Root_must_exists()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var resource = await testInit.ResourceProvider.Get(testInit.ResourceProvider.RootResourceId);
        Assert.IsNull(resource.ParentResourceId);
    }

    [TestMethod]
    public async Task Crud()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource
        {
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
        resource2 = await resourceProvider.Update(new Resource
        {
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
        try
        {
            await resourceProvider.Get(resource2.ResourceId);
            Assert.Fail("NotExistsException was expected.");

        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }
    }

    [TestMethod]
    public async Task Fail_loop_on_create()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);

        // loop on self
        try
        {
            var id1 = Guid.NewGuid().ToString();
            await testInit.ResourceProvider.Add(new Resource { ResourceId = id1, ParentResourceId = id1 });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }

    public async Task Fail_loop_on_update()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // loop on self
        try
        {
            var resource = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
            await resourceProvider.Update(new Resource { ResourceId = resource.ResourceId, ParentResourceId = resource.ResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }

        // deep loop
        var resource1 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resourceProvider.RootResourceId
        });

        var resource2 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource4 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        // loop on self
        try
        {
            await resourceProvider.Update(new Resource { ResourceId = resource1.ResourceId, ParentResourceId = resource4.ResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }

    [TestMethod]
    public async Task Delete_Recursive()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        var resource21 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource22 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });


        // ---------
        // Check: Delete
        // ---------
        await resourceProvider.Remove(resource1.ResourceId);
        try
        {
            await resourceProvider.Get(resource2.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }

        try
        {
            await resourceProvider.Get(resource21.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }

        try
        {
            await resourceProvider.Get(resource22.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }
    }

    [TestMethod]
    public async Task Delete_resource_must_delete_all_its_roles()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        var resourceProvider = testInit.ResourceProvider;

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Add(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Add(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });


        // create a user
        var userProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var userCreateRequest = new UserCreateRequest
        {
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
        Assert.IsTrue(userRoles.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId));

        // delete and get user roles again
        await testInit.ResourceProvider.Remove(resource2.ResourceId);
        userRoles = await userRoleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.IsFalse(userRoles.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId));
    }

    [TestMethod]
    public async Task Fail_removing_the_root()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);
        try
        {
            await testInit.ResourceProvider.Remove(testInit.ResourceProvider.RootResourceId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }

    [TestMethod]
    public async Task Fail_updating_root()
    {
        var testInit = await TestInit.Create(useResourceProvider: true);

        try
        {
            await testInit.ResourceProvider.Update(new Resource { ResourceId = testInit.ResourceProvider.RootResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }
}