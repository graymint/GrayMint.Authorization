using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Common.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Resource = GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos.Resource;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class SimpleResourceProviderTest
{
    [TestMethod]
    public async Task Root_must_exists()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();
        var resource = await resourceProvider.Get(resourceProvider.RootResourceId);
        Assert.IsNull(resource.ParentResourceId);
    }

    [TestMethod]
    public async Task Crud()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Create(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Create(new Resource
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
        await resourceProvider.Delete(resource2.ResourceId);
        try
        {
            await resourceProvider.Get(resource2.ResourceId);
            Assert.Fail("NotExistsException was expected.");

        }
        catch (Exception e)
        {
            Assert.IsTrue(NotExistsException.Is(e));
        }
    }

    [TestMethod]
    public async Task Fail_loop_on_create()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        // loop on self
        try
        {
            var id1 = Guid.NewGuid().ToString();
            await resourceProvider.Create(new Resource { ResourceId = id1, ParentResourceId = id1 });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(e);
        }
    }

    public async Task Fail_loop_on_update()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        // loop on self
        try
        {
            var resource = await resourceProvider.Create(new Resource { ResourceId = Guid.NewGuid().ToString() });
            await resourceProvider.Update(new Resource { ResourceId = resource.ResourceId, ParentResourceId = resource.ResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(e);
        }

        // deep loop
        var resource1 = await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resourceProvider.RootResourceId
        });

        var resource2 = await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource4 = await resourceProvider.Create(new Resource
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
        catch (Exception e)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(e);
        }
    }



    [TestMethod]
    public async Task Delete_Recursive()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        // ---------
        // Check: Create
        // ---------
        var resource1 = await resourceProvider.Create(new Resource { ResourceId = Guid.NewGuid().ToString() });
        var resource2 = await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource1.ResourceId
        });

        var resource21 = await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });

        var resource22 = await resourceProvider.Create(new Resource
        {
            ResourceId = Guid.NewGuid().ToString(),
            ParentResourceId = resource2.ResourceId
        });


        // ---------
        // Check: Delete
        // ---------
        await resourceProvider.Delete(resource1.ResourceId);
        try
        {
            await resourceProvider.Get(resource2.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsTrue(NotExistsException.Is(e));
        }

        try
        {
            await resourceProvider.Get(resource21.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsTrue(NotExistsException.Is(e));
        }

        try
        {
            await resourceProvider.Get(resource22.ResourceId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsTrue(NotExistsException.Is(e));
        }
    }

    [TestMethod]
    public async Task Fail_removing_the_root()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        try
        {
            await resourceProvider.Delete(resourceProvider.RootResourceId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(e);
        }
    }

    [TestMethod]
    public async Task Fail_updating_root()
    {
        var testInit = await TestInit.Create();
        var resourceProvider = testInit.Scope.ServiceProvider.GetRequiredService<SimpleResourceProvider>();

        try
        {
            await resourceProvider.Update(new Resource { ResourceId = resourceProvider.RootResourceId });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (Exception e)
        {
            Assert.IsInstanceOfType<InvalidOperationException>(e);
        }
    }

}