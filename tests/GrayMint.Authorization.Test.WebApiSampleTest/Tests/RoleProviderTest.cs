using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class RoleProviderTest
{
    [TestMethod]
    public async Task User_roles_total_counts_the_filtered_roles()
    {
        using var testInit = await TestInit.Create();
        var user = await testInit.UserProvider.Create(new UserCreateRequest { Email = TestInit.NewEmail() });
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        var resource1 = Guid.NewGuid().ToString();
        await roleProvider.AddUserRole(resource1, Roles.AppAdmin.RoleId, user.UserId);
        await roleProvider.AddUserRole(Guid.NewGuid().ToString(), Roles.AppAdmin.RoleId, user.UserId);

        // a full page of one resource's roles counts that resource's, not all of the user's
        var userRoles = await roleProvider.GetUserRoles(
            new UserRoleCriteria { UserId = user.UserId, ResourceId = resource1 }, recordIndex: 0, recordCount: 1);
        Assert.AreEqual(1, userRoles.TotalCount);
    }

    [TestMethod]
    public async Task Removing_roles_needs_a_criterion()
    {
        using var testInit = await TestInit.Create();
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await Assert.ThrowsAsync<ArgumentException>(() => roleProvider.RemoveUserRoles(new UserRoleCriteria()));
    }

    [TestMethod]
    public async Task Add_remove_user()
    {
        using var testInit = await TestInit.Create();

        // create a user
        var userCreateRequest = new UserCreateRequest {
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
        await roleProvider.AddUserRole(resource1, role.RoleId, user.UserId);
        await roleProvider.AddUserRole(resource2, role.RoleId, user.UserId);

        // Check user Roles
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.HasCount(2, userRoles);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Check user Roles
        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria
            { ResourceId = resource1, RoleId = role.RoleId });
        Assert.HasCount(1, userRoles);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource1 && x.Role.RoleName == role.RoleName));

        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria
            { ResourceId = resource2, RoleId = role.RoleId });
        Assert.HasCount(1, userRoles);
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == resource2 && x.Role.RoleName == role.RoleName));

        // Remove
        await roleProvider.RemoveUserRoles(new UserRoleCriteria
            { ResourceId = resource1, RoleId = role.RoleId, UserId = user.UserId });
        userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria
            { ResourceId = resource1, RoleId = role.RoleId, UserId = user.UserId });
        Assert.HasCount(0, userRoles);
    }

    [TestMethod]
    public async Task Role_added_by_another_form_of_user_id_applies_at_once()
    {
        using var testInit = await TestInit.Create();

        // the bot's roles are cached by its own id
        var bot = await testInit.AddNewBot(Roles.AppReader);
        await testInit.TeamClient.ListCurrentUserResourcesAsync();

        // a role added by the same id in upper case and without hyphens
        var otherFormId = Guid.Parse(bot.UserId).ToString("N").ToUpperInvariant();
        var resourceId = Guid.NewGuid().ToString();
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await roleProvider.AddUserRole(resourceId, Roles.AppReader.RoleId, otherFormId);

        var resourceIds = await testInit.TeamClient.ListCurrentUserResourcesAsync();
        Assert.Contains(resourceId, resourceIds);
    }

    [TestMethod]
    public async Task Permissions_on_made_up_resources_are_not_kept()
    {
        using var testInit = await TestInit.Create();
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();

        // the first lookup may cache the bot's own roles; the made-up resources after it add nothing
        await roleProvider.GetUserPermissions(Guid.NewGuid().ToString(), bot.UserId);
        var count = testInit.CountCacheEntries();
        for (var i = 0; i < 20; i++)
            Assert.HasCount(0, await roleProvider.GetUserPermissions(Guid.NewGuid().ToString(), bot.UserId));

        Assert.AreEqual(count, testInit.CountCacheEntries());
    }

    [TestMethod]
    public async Task GetAuthUser()
    {
        using var testInit = await TestInit.Create();

        // create a user
        var user = await testInit.UserProvider.Create(new UserCreateRequest {
            Email = $"{Guid.NewGuid()}@local",
            IsEmailVerified = true,
            IsPhoneVerified = true,
            PictureUrl = $"https://local/{Guid.NewGuid()}",
            Name = Guid.NewGuid().ToString(),
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            Description = Guid.NewGuid().ToString()
        });

        var systemRole = Roles.SystemAdmin;
        var role1 = Roles.AppAdmin;
        var role2 = Roles.AppReader;

        // Add the user to roles
        var roleProvider = testInit.Scope.ServiceProvider.GetRequiredService<IRoleProvider>();
        await roleProvider.AddUserRole(AuthorizationConstants.RootResourceId, systemRole.RoleId, user.UserId);
        await roleProvider.AddUserRole("1", role1.RoleId, user.UserId);
        await roleProvider.AddUserRole("1", role2.RoleId, user.UserId);

        // check authorization code
        var identity = new ClaimsIdentity();
        if (user.Email != null)
            identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        var authorizationProvider = testInit.Scope.ServiceProvider.GetRequiredService<IAuthorizationProvider>();
        var userId = await authorizationProvider.GetUserId(new ClaimsPrincipal(identity));
        Assert.IsNotNull(userId);
        user = await testInit.UserProvider.Get(userId);
        var authorizationCode = await authorizationProvider.GetAuthorizationCode(new ClaimsPrincipal(identity));
        Assert.AreEqual(user.AuthorizationCode, authorizationCode);

        // check user role
        var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { UserId = user.UserId });
        Assert.HasCount(3, userRoles);
        Assert.IsTrue(userRoles.Any(x =>
            x.ResourceId == AuthorizationConstants.RootResourceId && x.Role.RoleName == systemRole.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == "1" && x.Role.RoleName == role1.RoleName));
        Assert.IsTrue(userRoles.Any(x => x.ResourceId == "1" && x.Role.RoleName == role2.RoleName));
    }
}