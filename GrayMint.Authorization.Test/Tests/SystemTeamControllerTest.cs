using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.WebApiSample.Security;
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

        var apiKey = await testInit.TeamClient.AddNewBotAsync(0, new TeamAddBotParam
        {
            Name = Guid.NewGuid().ToString(),
            RoleId = Roles.SystemAdmin.RoleId
        });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserAsync(0, new TeamAddUserParam
        {
            Email = TestInit.NewEmail(),
            RoleId = Roles.SystemAdmin.RoleId
        });
    }

    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await TestInit.Create();

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(0);
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
        var addUserParam1 = new TeamAddUserParam
        {
            Email = TestInit.NewEmail(),
            RoleId = Roles.SystemAdmin.RoleId
        };
        var userRole1 = await testInit.TeamClient.AddUserAsync(0, addUserParam1);
        Assert.IsNotNull(userRole1.User);
        Assert.AreEqual(userRole1.User.Email, addUserParam1.Email);
        Assert.AreEqual(userRole1.Role.RoleId, addUserParam1.RoleId);

        var addUserParam2 = new TeamAddUserParam
        {
            Email = TestInit.NewEmail(),
            RoleId = Roles.SystemAdmin.RoleId
        };
        var userRole2 = await testInit.TeamClient.AddUserAsync(0, addUserParam2);
        Assert.IsNotNull(userRole2.User);


        // ---------
        // Get
        // ---------
        var userRole = await testInit.TeamClient.GetUserAsync(0, userRole1.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(userRole.User.Email, addUserParam1.Email);
        Assert.AreEqual(userRole.Role.RoleId, addUserParam1.RoleId);

        userRole = await testInit.TeamClient.UpdateUserAsync(0, userRole1.User.UserId, new TeamUpdateUserParam
        {
            RoleId = new PatchOfGuid { Value = Roles.SystemReader.RoleId }
        });
        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);
        userRole = await testInit.TeamClient.GetUserAsync(0, userRole1.User.UserId);
        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);

        // ---------
        // List Users
        // ---------
        var users = await testInit.TeamClient.ListUsersAsync(0);
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole1.User.UserId));
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole2.User?.UserId));

        // ---------
        // Remove Users
        // ---------
        await testInit.TeamClient.RemoveUserAsync(0, userRole2.User.UserId);
        users = await testInit.TeamClient.ListUsersAsync(0);
        Assert.IsTrue(users.Items.Any(x => x.User?.UserId == userRole1.User.UserId));
        Assert.IsTrue(users.Items.All(x => x.User?.UserId != userRole2.User.UserId));
    }
}