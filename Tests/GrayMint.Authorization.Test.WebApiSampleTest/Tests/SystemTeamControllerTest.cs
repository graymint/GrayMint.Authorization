using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Test.Api;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class SystemTeamControllerTest
{
    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await TestInit.Create();

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.RootResourceId, Roles.SystemAdmin.RoleId, new TeamAddBotParam
        {
            Name = Guid.NewGuid().ToString()
        });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, Roles.SystemAdmin.RoleId, TestInit.NewEmail());
    }

    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await TestInit.Create();

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(testInit.RootResourceId);
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.SystemAdmin.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.SystemReader.RoleId));
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.AppOwner.RoleId));
    }

    [TestMethod]
    public async Task User_Crud()
    {
        // ---------
        // Create
        // ---------
        using var testInit = await TestInit.Create();
        var email1 = TestInit.NewEmail();
        var roleId1 = Roles.SystemAdmin.RoleId;
        var userRole1 = await testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, roleId1, email1);
        Assert.IsNotNull(userRole1.User);
        Assert.AreEqual(userRole1.User.Email, email1);
        Assert.AreEqual(userRole1.Role.RoleId, roleId1);

        var email2 = TestInit.NewEmail();
        var roleId2 = Roles.SystemAdmin.RoleId;
        var userRole2 = await testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, roleId2, email2);
        Assert.IsNotNull(userRole2.User);


        // ---------
        // Get
        // ---------
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.RootResourceId, userId: userRole1.User.UserId);
        var userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(userRole.User.Email, email1);
        Assert.AreEqual(userRole.Role.RoleId, roleId1);

        userRole = await testInit.TeamClient.AddUserAsync(testInit.RootResourceId, Roles.SystemReader.RoleId, userRole1.User.UserId);
        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);
        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.RootResourceId, userId: userRole1.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);

        // ---------
        // List Users
        // ---------
        var users = await testInit.TeamClient.ListUserRolesAsync(testInit.RootResourceId);
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole1.User.UserId));
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole2.User?.UserId));

        // ---------
        // Remove Users
        // ---------
        await testInit.TeamClient.RemoveUserAsync(testInit.RootResourceId, userRole2.Role.RoleId, userRole2.User.UserId);
        users = await testInit.TeamClient.ListUserRolesAsync(testInit.RootResourceId);
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole1.User.UserId));
        Assert.IsTrue(users.Items.All(x => x.User?.UserId != userRole2.User.UserId));
    }
}