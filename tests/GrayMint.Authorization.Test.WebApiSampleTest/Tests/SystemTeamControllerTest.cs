using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Test.Api;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class SystemTeamControllerTest : TestBase
{
    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await CreateTestInit();

        var apiKey = await testInit.TeamClient.AddNewBotAsync(TestInit.RootResourceId, Roles.SystemAdmin.RoleId,
            new TeamAddBotParam {
                Name = Guid.NewGuid().ToString()
            });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserByEmailAsync(TestInit.RootResourceId, Roles.SystemAdmin.RoleId,
            TestInit.NewEmail());
    }

    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await CreateTestInit();

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(TestInit.RootResourceId);
        Assert.Contains(x => x.RoleId == Roles.SystemAdmin.RoleId, roles);
        Assert.Contains(x => x.RoleId == Roles.SystemReader.RoleId, roles);
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.AppOwner.RoleId));
    }

    [TestMethod]
    public async Task User_Crud()
    {
        // ---------
        // Create
        // ---------
        using var testInit = await CreateTestInit();
        var email1 = TestInit.NewEmail();
        var roleId1 = Roles.SystemAdmin.RoleId;
        var userRole1 = await testInit.TeamClient.AddUserByEmailAsync(TestInit.RootResourceId, roleId1, email1);
        Assert.IsNotNull(userRole1.User);
        Assert.AreEqual(userRole1.User.Email, email1);
        Assert.AreEqual(userRole1.Role.RoleId, roleId1);

        var email2 = TestInit.NewEmail();
        var roleId2 = Roles.SystemAdmin.RoleId;
        var userRole2 = await testInit.TeamClient.AddUserByEmailAsync(TestInit.RootResourceId, roleId2, email2);
        Assert.IsNotNull(userRole2.User);


        // ---------
        // Get
        // ---------
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: TestInit.RootResourceId,
                userId: userRole1.User.UserId);

        var userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(userRole.User.Email, email1);
        Assert.AreEqual(userRole.Role.RoleId, roleId1);

        userRole = await testInit.TeamClient.AddUserAsync(TestInit.RootResourceId, Roles.SystemReader.RoleId,
            userRole1.User.UserId);

        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);
        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: TestInit.RootResourceId,
            userId: userRole1.User.UserId);

        userRole = userRoles.Items.Single();
        Assert.AreEqual(Roles.SystemReader.RoleId, userRole.Role.RoleId);


        // ---------
        // Get By Id
        // ---------
        var teamUser =
            await testInit.TeamClient.GetUserAsync(resourceId: TestInit.RootResourceId, userRole1.User.UserId);

        Assert.HasCount(userRoles.Items.Count, teamUser.Roles);

        // ---------
        // Get By Email
        // ---------
        teamUser = await testInit.TeamClient.GetUserByEmailAsync(resourceId: TestInit.RootResourceId,
            email1);

        Assert.HasCount(userRoles.Items.Count, teamUser.Roles);

        // ---------
        // List Users
        // ---------
        var users = await testInit.TeamClient.ListUserRolesAsync(TestInit.RootResourceId);
        Assert.Contains(x => x.User?.UserId == userRole1.User.UserId, users.Items);
        Assert.Contains(x => x.User?.UserId == userRole2.User?.UserId, users.Items);

        // ---------
        // Remove Users
        // ---------
        await testInit.TeamClient.RemoveUserAsync(TestInit.RootResourceId, userRole2.Role.RoleId,
            userRole2.User.UserId);

        users = await testInit.TeamClient.ListUserRolesAsync(TestInit.RootResourceId);
        Assert.Contains(x => x.User?.UserId == userRole1.User.UserId, users.Items);
        Assert.IsTrue(users.Items.All(x => x.User?.UserId != userRole2.User.UserId));
    }
}