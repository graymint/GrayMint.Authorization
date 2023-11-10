using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Utils;
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
            Phone = "+1" + Random.Shared.Next(1_000_000_000, 2_000_000_000),
            IsDisabled = true,
            IsEmailVerified = true,
            IsPhoneVerified = true,
            PictureUrl = $"https://local/{Guid.NewGuid()}",
            Name = Guid.NewGuid().ToString(),
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString(),
            ExData = "zz"
        };

        var user = await simpleUserProvider.Create(request);
        Assert.AreEqual(request.Email, user.Email);
        Assert.AreEqual(request.Name, user.Name);
        Assert.AreEqual(request.FirstName, user.FirstName);
        Assert.AreEqual(request.LastName, user.LastName);
        Assert.AreEqual(request.Phone, user.Phone);
        Assert.AreEqual(request.Description, user.Description);
        Assert.AreEqual(request.ExData, user.ExData);
        Assert.AreEqual(request.IsPhoneVerified, user.IsPhoneVerified);
        Assert.AreEqual(request.IsDisabled, user.IsDisabled);
        Assert.AreEqual(request.IsEmailVerified, user.IsEmailVerified);
        Assert.AreEqual(request.PictureUrl, user.PictureUrl);
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
            Name = Guid.NewGuid().ToString(),
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            PictureUrl = $"https://local/{Guid.NewGuid()}",
            Description = Guid.NewGuid().ToString(),
            Email = $"{Guid.NewGuid()}@local",
            Phone = "+1" + Random.Shared.Next(1_000_000_000, 2_000_000_000),
            IsEmailVerified = false,
            IsPhoneVerified = false,
            IsDisabled = false,
            ExData = Guid.NewGuid().ToString(),
            
        };
        await simpleUserProvider.Update(user.UserId, updateRequest);

        // Get
        var user4 = await simpleUserProvider.Get(user.UserId);
        Assert.AreEqual(user4.Email, updateRequest.Email.Value);
        Assert.AreEqual(user4.Name, updateRequest.Name.Value);
        Assert.AreEqual(user4.FirstName, updateRequest.FirstName.Value);
        Assert.AreEqual(user4.LastName, updateRequest.LastName.Value);
        Assert.AreEqual(user4.Phone, updateRequest.Phone.Value);
        Assert.AreEqual(user4.PictureUrl, updateRequest.PictureUrl.Value);
        Assert.AreEqual(user4.Description, updateRequest.Description.Value);
        Assert.AreEqual(user4.AuthorizationCode, user.AuthorizationCode);

        // Remove
        await simpleUserProvider.Remove(user.UserId);
        await TestUtil.AssertNotExistsException(
            simpleUserProvider.Get(user.UserId));
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
        await TestUtil.AssertAlreadyExistsException(
            simpleUserProvider.Create(request));
    }
}