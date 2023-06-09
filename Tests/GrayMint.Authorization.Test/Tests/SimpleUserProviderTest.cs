using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class SimpleUserProviderTest 
{
    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await TestInit.Create();

        // Create
        var simpleUserProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var request = new UserCreateRequest
        {
            Email = $"{Guid.NewGuid()}@local",
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString(),
            ExData = "zz"
        };

        var user = await simpleUserProvider.Create(request);
        Assert.AreEqual(request.Email, user.Email);
        Assert.AreEqual(request.FirstName, user.FirstName);
        Assert.AreEqual(request.LastName, user.LastName);
        Assert.AreEqual(request.Description, user.Description);
        Assert.AreEqual(request.ExData, user.ExData);
        Assert.IsNotNull(user.AuthorizationCode);
        Assert.AreNotEqual(string.Empty, user.AuthorizationCode.Trim());



        // Get
        var user2 = await simpleUserProvider.Get(user.UserId);
        Assert.AreEqual(user.Email, user2.Email);
        Assert.AreEqual(user.FirstName, user2.FirstName);
        Assert.AreEqual(user.LastName, user2.LastName);
        Assert.AreEqual(user.Description, user2.Description);
        Assert.AreEqual(user.AuthorizationCode, user2.AuthorizationCode);
        Assert.AreEqual(user.CreatedTime, user2.CreatedTime);
        Assert.AreEqual(user.UserId, user2.UserId);

        var user3 = await simpleUserProvider.GetByEmail(user.Email);
        Assert.AreEqual(user.UserId, user3.UserId);
        Assert.AreEqual(user.FirstName, user3.FirstName);

        // Update
        var updateRequest = new UserUpdateRequest()
        {
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString(),
            Email = $"{Guid.NewGuid()}@local"
        };
        await simpleUserProvider.Update(user.UserId, updateRequest);

        // Get
        var user4 = await simpleUserProvider.Get(user.UserId);
        Assert.AreEqual(user4.Email, updateRequest.Email.Value);
        Assert.AreEqual(user4.FirstName, updateRequest.FirstName.Value);
        Assert.AreEqual(user4.LastName, updateRequest.LastName.Value);
        Assert.AreEqual(user4.Description, updateRequest.Description.Value);
        Assert.AreEqual(user4.AuthorizationCode, user.AuthorizationCode);

        // Remove
        await simpleUserProvider.Remove(user.UserId);
        try
        {
            await simpleUserProvider.Get(user.UserId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }
    }

    [TestMethod]
    public async Task Fail_Already_exist()
    {
        using var testInit = await TestInit.Create();

        // Create
        var simpleUserProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var request = new UserCreateRequest
        {
            Email = $"{Guid.NewGuid()}@local",
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        };
        await simpleUserProvider.Create(request);

        // AlreadyExists exception
        try
        {
            await simpleUserProvider.Create(request);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(AlreadyExistsException.Is(ex));
        }
    }
}