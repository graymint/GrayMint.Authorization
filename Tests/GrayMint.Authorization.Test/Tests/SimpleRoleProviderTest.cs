using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class SimpleRoleProviderTest 
{

    [TestMethod]
    public async Task Add_remove_user()
    {
        using var testInit = await TestInit.Create();

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

        // create a role
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        var role = Roles.AppAdmin;

        // Add the user to roles
        var resource1 = Guid.NewGuid().ToString();
        var resource2 = Guid.NewGuid().ToString();
        await roleProvider.AddUser(resource1, role.RoleId, user.UserId);
        await roleProvider.AddUser(resource2, role.RoleId, user.UserId);

        // Check user Roles
        var userRoles = await roleProvider.GetUserRoles(userId: user.UserId);
        Assert.AreEqual(2, userRoles.TotalCount);
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Check user Roles
        userRoles = await roleProvider.GetUserRoles(resourceId: resource1, roleId: role.RoleId);
        Assert.AreEqual(1, userRoles.TotalCount);
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));
        
        userRoles = await roleProvider.GetUserRoles(resourceId: resource2, roleId: role.RoleId);
        Assert.AreEqual(1, userRoles.TotalCount);
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Remove
        await roleProvider.RemoveUser(resource1, role.RoleId, user.UserId);
        try
        {
            await roleProvider.RemoveUser(resource1, role.RoleId, user.UserId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (Exception ex)
        {
            Assert.IsTrue(NotExistsException.Is(ex));
        }
    }

    [TestMethod]
    public async Task GetAuthUser()
    {
        using var testInit = await TestInit.Create();

        // create a user
        var userProvider = testInit.Scope.ServiceProvider.GetRequiredService<IUserProvider>();
        var user = await userProvider.Create(new UserCreateRequest
        {
            Email = $"{Guid.NewGuid()}@local",
            IsEmailVerified = true,
            IsPhoneVerified = true,
            PictureUrl = $"https://local/{Guid.NewGuid()}",
            Name = Guid.NewGuid().ToString(),
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        });

        var role1 = Roles.AppAdmin;
        var role2 = Roles.AppReader;

        // Add the user to roles
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await roleProvider.AddUser(AuthorizationConstants.RootResourceId, role1.RoleId, user.UserId);
        await roleProvider.AddUser("1", role1.RoleId, user.UserId);
        await roleProvider.AddUser("1", role2.RoleId, user.UserId);

        // check authorization code
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(ClaimTypes.Email, user.Email) );
        var authorizationProvider = testInit.Scope.ServiceProvider.GetRequiredService<IAuthorizationProvider>();
        var userId = await authorizationProvider.GetUserId(new ClaimsPrincipal(identity));
        Assert.IsNotNull(userId);
        user = await userProvider.Get(Guid.Parse(userId));
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(identity));
        Assert.AreEqual(user.AuthorizationCode, authorizationCode);
        
        // check user role
        var userRoles = await roleProvider.GetUserRoles(userId: user.UserId);
        Assert.AreEqual(3, userRoles.TotalCount);
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == AuthorizationConstants.RootResourceId && x.Role.RoleName == role1.RoleName));
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == "1" && x.Role.RoleName == role1.RoleName));
        Assert.IsTrue(userRoles.Items.Any(x => x.ResourceId == "1" && x.Role.RoleName == role2.RoleName));
    }
}