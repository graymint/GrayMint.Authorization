using System.Net;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class TeamControllerTest
{
    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await TestInit.Create();

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId,
            new TeamAddBotParam
            {
                Name = Guid.NewGuid().ToString()
            });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId,
            TestInit.NewEmail(), new TeamAddEmailParam());
    }

    [TestMethod]
    public async Task Bot_update()
    {
        using var testInit = await TestInit.Create();

        var apiKey = await testInit.AddNewBot(Roles.AppWriter, false);
        var newName = Guid.NewGuid().ToString();
        var user = await testInit.TeamClient.UpdateBotAsync(apiKey.UserId,
            new TeamUpdateBotParam { Name = new PatchOfString { Value = newName } });
        Assert.AreEqual(newName, user.FirstName);

        var userRole = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: apiKey.UserId);
        Assert.AreEqual(newName, userRole.Items.SingleOrDefault()?.User?.FirstName);
    }

    [TestMethod]
    public async Task GetUserPermissions_SingleRole()
    {
        using var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.AppReader);
        var permissions = await testInit.TeamClient.ListCurrentUserPermissionsAsync(testInit.AppResourceId);
        foreach (var permission in Roles.AppReader.Permissions)
            Assert.Contains(permission, permissions);

        Assert.HasCount(Roles.AppReader.Permissions.Length, permissions);
    }

    [TestMethod]
    public async Task GetUserPermissions_MultiRole()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true);
        var apiKey = await testInit.AddNewBot(Roles.AppReader, false);
        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId);
        testInit.SetApiKey(apiKey);

        var permissions = await testInit.TeamClient.ListCurrentUserPermissionsAsync(testInit.AppResourceId);
        foreach (var permission in Roles.AppReader.Permissions)
            Assert.Contains(permission, permissions);

        foreach (var permission in Roles.AppWriter.Permissions)
            Assert.Contains(permission, permissions);

        Assert.HasCount(Roles.AppReader.Permissions.Union(Roles.AppAdmin.Permissions).Distinct().Count(), permissions);
    }


    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await TestInit.Create();

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(testInit.AppResourceId);
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemAdmin.RoleId));
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemReader.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppOwner.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppReader.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppWriter.RoleId));
    }

    [TestMethod]
    public async Task List_UserApps()
    {
        using var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.AppOwner);
        var apps = await testInit.TeamClient.ListCurrentUserAppsAsync();
        Assert.IsTrue(apps.Any(x => x.AppId == testInit.AppId));
    }

    [TestMethod]
    public async Task Bot_can_not_be_created_as_owner()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { { "TeamController:AllowBotAppOwner", "false" } });

        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, 
            new TeamAddBotParam { Name = Guid.NewGuid().ToString() }));
    }

    [TestMethod]
    public async Task Bot_can_not_be_added_to_owners()
    {
        using var testInit = await TestInit.Create(appSettings: new Dictionary<string, string?> { { "TeamController:AllowBotAppOwner", "false" } });
        var apiKey = await testInit.AddNewBot(Roles.AppWriter, setAsCurrent: false);
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, apiKey.UserId));
    }


    [TestMethod]
    public async Task Bot_can_not_be_added_if_it_belong_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppResourceId, userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        using var testInit2 = await TestInit.Create();
        await testInit2.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit2.TeamClient.AddUserByEmailAsync(testInit2.AppResourceId, Roles.AppAdmin.RoleId, botUserRole.User!.Email!));

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit2.TeamClient.AddUserAsync(testInit2.AppResourceId, Roles.AppAdmin.RoleId, botUserRole.User!.UserId));
    }


    [TestMethod]
    public async Task Bot_can_not_be_reset_if_belongs_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppResourceId, userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        using var testInit2 = await TestInit.Create();
        await testInit2.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit2.TeamClient.ResetBotApiKeyAsync(botUserRole.User!.UserId));
    }

    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await TestInit.Create();

        // create
        var roleId = Roles.AppAdmin.RoleId;
        var email = $"{Guid.NewGuid()}@mail.com";
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, roleId, email);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // get
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: userRole.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // add to another role
        roleId = Roles.AppReader.RoleId;
        userRole = await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: roleId, userId: userRole.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: userRole.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // delete
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, roleId, userRole.User.UserId);
        var userRoleResult = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userRole.User.UserId);
        Assert.IsEmpty(userRoleResult.Items);
    }


    [TestMethod]
    public async Task User_already_exists()
    {
        using var testInit = await TestInit.Create();

        // create
        var email = $"{Guid.NewGuid()}@mail.com";
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, email);
        await TestUtil.AssertApiException<AlreadyExistsException>(
            testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, email));
    }

    [TestMethod]
    public async Task List_Users()
    {
        using var testInit = await TestInit.Create();

        // create
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        Assert.IsNotNull(userRole1.User);

        var userRole2 = await testInit.AddNewUser(Roles.AppReader);
        Assert.IsNotNull(userRole2.User);

        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId);
        var userRole1B = userRoles.Items.Single(x => x.User?.UserId == userRole1.User.UserId);
        var userRole2B = userRoles.Items.Single(x => x.User?.UserId == userRole2.User.UserId);
        Assert.IsNotNull(userRole1B.User);
        Assert.IsNotNull(userRole2B.User);

        Assert.AreEqual(userRole1.User.Email, userRole1B.User.Email);
        Assert.AreEqual(userRole1.User.UserId, userRole1B.User.UserId);
        Assert.AreEqual(userRole1.Role.RoleId, userRole1B.Role.RoleId);

        Assert.AreEqual(userRole2.User.Email, userRole2B.User.Email);
        Assert.AreEqual(userRole2.User.UserId, userRole2B.User.UserId);
        Assert.AreEqual(userRole2.Role.RoleId, userRole2B.Role.RoleId);
    }

    [TestMethod]
    public async Task Owner_should_not_be_changed_by_admins()
    {
        using var testInit = await TestInit.Create();
        var ownerApiKey = await testInit.AddNewBot(Roles.AppOwner, false);
        var adminApiKey = await testInit.AddNewBot(Roles.AppAdmin);

        // ---------------
        // Check: add
        // ---------------
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.AddNewUser(Roles.AppOwner));

        // ---------------
        // Check: update
        // ---------------
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, adminApiKey.UserId));

        // ---------------
        // Check: remove
        // ---------------
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, ownerApiKey.UserId));

    }

    [TestMethod]
    public async Task Owner_can_add_or_update_himself_to_other_role_in_MultiRole()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true);
        var apiKey = await testInit.AddNewBot(Roles.AppOwner);

        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: apiKey.UserId);
        Assert.AreEqual(1, userRoles.TotalCount);
        Assert.AreEqual(Roles.AppOwner.RoleId, userRoles.Items.Single().Role.RoleId);
    }

    [TestMethod]
    public async Task Owner_should_not_remove_update_his_role()
    {
        using var testInit = await TestInit.Create();
        var apiKey = await testInit.AddNewBot(Roles.AppOwner);

        // ---------------
        // Check: update
        // ---------------
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId));

        // ---------------
        // Check: remove
        // ---------------
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, apiKey.UserId));

    }

    [TestMethod]
    public async Task Owner_should_remove_other()
    {
        using var testInit = await TestInit.Create();
        var ownerUserRole = await testInit.AddNewUser(Roles.AppOwner);
        await testInit.AddNewBot(Roles.AppOwner);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, ownerUserRole.Role.RoleId, ownerUserRole.User!.UserId);
    }

    [TestMethod]
    public async Task Multi_roles()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true);
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: Roles.AppReader.RoleId, userId: userRole1.UserId);
        var appRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: userRole1.UserId);
        Assert.AreEqual(2, appRoles.TotalCount);
        Assert.HasCount(2, appRoles.Items);
        Assert.IsTrue(appRoles.Items.Any(x => x.Role.RoleId == Roles.AppAdmin.RoleId));
        Assert.IsTrue(appRoles.Items.Any(x => x.Role.RoleId == Roles.AppReader.RoleId));
    }

    [TestMethod]
    public async Task AppAdmin_add_a_root_user_to_his_app()
    {
        // ---------
        // Create
        // ---------
        using var testInit = await TestInit.Create();

        var systemAdmin = await testInit.AddNewUser(Roles.SystemAdmin);
        await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, systemAdmin.UserId);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: systemAdmin.UserId);
        var userRole = userRoles.Items.Single();
        Assert.AreEqual(Roles.AppReader.RoleId, userRole.Role.RoleId);

        // remove it
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, systemAdmin.UserId);
        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId, userId: systemAdmin.UserId);
        userRole = userRoles.Items.SingleOrDefault();
        Assert.IsNull(userRole);
    }
}