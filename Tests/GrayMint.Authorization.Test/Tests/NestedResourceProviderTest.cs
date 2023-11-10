using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Dtos;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class NestedResourceProviderTest
{
    [TestMethod]
    public async Task AppUser_access_by_hierarchy_permission()
    {
        var testInit1 = await TestInit.Create(useNestedResource: true);
        var testInit2 = await TestInit.Create(useNestedResource: true);
        var testInit3 = await TestInit.Create(useNestedResource: true);

        // -------------
        // Check: Failed if there is no hierarchy 
        // -------------
        testInit3.SetApiKey(await testInit1.AddNewBot(Roles.AppWriter));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit3.ItemsClient.CreateByPermissionAsync(testInit3.App.AppId, Guid.NewGuid().ToString()));

        // Set hierarchy
        await testInit1.NestedResourceProvider.Update(new Resource { ResourceId = testInit2.AppId.ToString(), ParentResourceId = testInit1.AppId.ToString() });
        await testInit1.NestedResourceProvider.Update(new Resource { ResourceId = testInit3.AppId.ToString(), ParentResourceId = testInit2.AppId.ToString() });

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

    [TestMethod]
    public async Task Root_must_exists()
    {
        var testInit = await TestInit.Create(useNestedResource: true);
        var resource = await testInit.NestedResourceProvider.Get(testInit.NestedResourceProvider.RootResourceId);
        Assert.IsNull(resource.ParentResourceId);
    }

    [TestMethod]
    public async Task Crud()
    {
        var testInit = await TestInit.Create(useNestedResource: true);
        var resourceProvider = testInit.NestedResourceProvider;

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
        var testInit = await TestInit.Create(useNestedResource: true);

        // loop on self
        try
        {
            var id1 = Guid.NewGuid().ToString();
            await testInit.NestedResourceProvider.Add(new Resource { ResourceId = id1, ParentResourceId = id1 });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }

    public async Task Fail_loop_on_update()
    {
        var testInit = await TestInit.Create(useNestedResource: true);
        var resourceProvider = testInit.NestedResourceProvider;

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
        var testInit = await TestInit.Create(useNestedResource: true);
        var resourceProvider = testInit.NestedResourceProvider;

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
        var testInit = await TestInit.Create(useNestedResource: true);
        var resourceProvider = testInit.NestedResourceProvider;

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
        await testInit.NestedResourceProvider.Remove(resource2.ResourceId);
        userRoles = await userRoleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.IsFalse(userRoles.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId));
    }

    [TestMethod]
    public async Task Fail_removing_the_root()
    {
        var testInit = await TestInit.Create(useNestedResource: true);
        try
        {
            await testInit.NestedResourceProvider.Remove(testInit.NestedResourceProvider.RootResourceId);
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
        var testInit = await TestInit.Create(useNestedResource: true);

        try
        {
            await testInit.NestedResourceProvider.Update(new Resource { ResourceId = testInit.NestedResourceProvider.RootResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(ex);
        }
    }
}