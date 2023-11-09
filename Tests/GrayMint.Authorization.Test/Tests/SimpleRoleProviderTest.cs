using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.Abstractions;
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
        var userCreateRequest = new UserCreateRequest
        {
            Email = $"{Guid.NewGuid()}@local",
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        };
        var user = await testInit.UserProvider.Create(userCreateRequest);

        // create a role
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        var role = Roles.AppAdmin;

        // Add the user to roles
        var resource1 = Guid.NewGuid().ToString();
        var resource2 = Guid.NewGuid().ToString();
        await testInit.ResourceProvider.Add(new Resource { ResourceId = resource1 });
        await testInit.ResourceProvider.Add(new Resource { ResourceId = resource2 });

        await roleProvider.AddUserRole(resource1, role.RoleId, user.UserId);
        await roleProvider.AddUserRole(resource2, role.RoleId, user.UserId);

        // Check user Roles
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.AreEqual(2, userRoles.Length);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Check user Roles
        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resource1, RoleId = role.RoleId });
        Assert.AreEqual(1, userRoles.Length);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));

        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resource2, RoleId = role.RoleId });
        Assert.AreEqual(1, userRoles.Length);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Remove
        await roleProvider.RemoveUserRoles(new UserRoleCriteria { ResourceId = resource1, RoleId = role.RoleId, UserId = user.UserId });
        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resource1, RoleId = role.RoleId, UserId = user.UserId });
        Assert.AreEqual(0, userRoles.Length);
    }

    [TestMethod]
    public async Task GetAuthUser()
    {
        using var testInit = await TestInit.Create();

        // create a user
        var user = await testInit.UserProvider.Create(new UserCreateRequest
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
        await roleProvider.AddUserRole(AuthorizationConstants.RootResourceId, role1.RoleId, user.UserId);
        await roleProvider.AddUserRole("1", role1.RoleId, user.UserId);
        await roleProvider.AddUserRole("1", role2.RoleId, user.UserId);

        // check authorization code
        var identity = new ClaimsIdentity();
        identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        var authorizationProvider = testInit.Scope.ServiceProvider.GetRequiredService<IAuthorizationProvider>();
        var userId = await authorizationProvider.GetUserId(new ClaimsPrincipal(identity));
        Assert.IsNotNull(userId);
        user = await testInit.UserProvider.Get(userId);
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(identity));
        Assert.AreEqual(user.AuthorizationCode, authorizationCode);

        // check user role
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.AreEqual(3, userRoles.Length);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == AuthorizationConstants.RootResourceId && x.Role.RoleName == role1.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == "1" && x.Role.RoleName == role1.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == "1" && x.Role.RoleName == role2.RoleName));
    }
}