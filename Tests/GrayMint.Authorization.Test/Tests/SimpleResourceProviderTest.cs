using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Resource = GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos.Resource;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class ResourceProviderTest
{
    [TestMethod]
    public async Task Root_must_exists()
    {
        var testInit = await TestInit.Create();
        var resource = await testInit.ResourceProvider.Get(testInit.ResourceProvider.RootResourceId);
        Assert.IsNull(resource.ParentResourceId);
    }

    [TestMethod]
    public async Task Crud()
    {
        var testInit = await TestInit.Create();
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
        var testInit = await TestInit.Create();

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
        var testInit = await TestInit.Create();
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
        var testInit = await TestInit.Create();
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
        var testInit = await TestInit.Create();
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
        var simpleUserProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var userCreateRequest = new UserCreateRequest
        {
            Email = $"{Guid.NewGuid()}@local",
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        };
        var user = await simpleUserProvider.Create(userCreateRequest);

        // assign role
        var userRoleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await userRoleProvider.AddUser(resource2.ResourceId, Roles.AppAdmin.RoleId, user.UserId);

        // get user roles
        var userRoles = await userRoleProvider.GetUserRoles(userId: user.UserId);
        Assert.IsTrue(userRoles.Items.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId));

        // delete and get user roles again
        await testInit.ResourceProvider.Remove(resource2.ResourceId);
        userRoles = await userRoleProvider.GetUserRoles(userId: user.UserId);
        Assert.IsFalse(userRoles.Items.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId && x.ResourceId == resource2.ResourceId));
    }

    [TestMethod]
    public async Task Fail_removing_the_root()
    {
        var testInit = await TestInit.Create();
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
        var testInit = await TestInit.Create();

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