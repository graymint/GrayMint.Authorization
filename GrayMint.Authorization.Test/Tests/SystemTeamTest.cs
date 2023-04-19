using System.Net;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class AppTeamControllerTest
{
    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await TestInit.Create();

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.AppId, Roles.AppAdmin.RoleId,
            new TeamAddBotParam
            {
                Name = Guid.NewGuid().ToString(),
            });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppId, Roles.AppAdmin.RoleId,
            TestInit.NewEmail(), new TeamAddEmailParam());
    }

    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await TestInit.Create();

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(testInit.AppId);
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemAdmin.RoleId));
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemReader.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppOwner.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppReader.RoleId));
        Assert.IsTrue(roles.Any(x => x.RoleId == Roles.AppWriter.RoleId));
    }

    [TestMethod]
    public async Task List_UserApps()
    {
        using var testInit1 = await TestInit.Create();
        await testInit1.AddNewBot(Roles.AppOwner);
        var apps = await testInit1.TeamClient.ListCurrentUserResourcesAsync();
        Assert.IsTrue(apps.Any(x => x.AppId == testInit1.AppId));
    }

    [TestMethod]
    public async Task Bot_can_not_be_owner()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { { "TeamController:AllowBotAppOwner", "false" } });

        // --------
        // Check: Bot can't be an owner
        // --------
        try
        {
            await testInit.TeamClient.AddNewBotAsync(testInit.AppId, Roles.AppOwner.RoleId, new TeamAddBotParam
            {
                Name = Guid.NewGuid().ToString(),
            });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    [TestMethod]
    public async Task Bot_can_not_be_added_if_it_belong_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppId, userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        // change the current user to another resource
        using var testInit2 = await TestInit.Create();
        await testInit2.AddNewBot(Roles.AppAdmin);
        try
        {
            await testInit2.TeamClient.AddUserByEmailAsync(testInit2.AppId, Roles.AppAdmin.RoleId, botUserRole.User!.Email);
            Assert.Fail("UnauthorizedAccessException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(UnauthorizedAccessException), ex.ExceptionTypeName);
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }

        try
        {
            await testInit2.TeamClient.AddUserAsync(testInit2.AppId, Roles.AppAdmin.RoleId, botUserRole.User!.UserId);
            Assert.Fail("UnauthorizedAccessException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(UnauthorizedAccessException), ex.ExceptionTypeName);
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }
    }


    [TestMethod]
    public async Task Bot_can_not_be_reset_if_it_belong_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppId, userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        // change the current user to another resource
        using var testInit2 = await TestInit.Create();
        await testInit2.AddNewBot(Roles.AppAdmin);
        try
        {
            await testInit2.TeamClient.ResetBotApiKeyAsync(apiKey1.UserId);
            Assert.Fail("UnauthorizedAccessException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(UnauthorizedAccessException), ex.ExceptionTypeName);
            Assert.AreEqual((int)HttpStatusCode.Forbidden, ex.StatusCode);
        }
    }

    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await TestInit.Create();

        // create
        var roleId = Roles.AppAdmin.RoleId;
        var email = $"{Guid.NewGuid()}@mail.com";
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppId, roleId, email);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // get
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppId, userId: userRole.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // add to another role
        roleId = Roles.AppReader.RoleId;
        userRole = await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppId, roleId: roleId, userId: userRole.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppId, userId: userRole.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // delete
        await testInit.TeamClient.RemoveUserAsync(testInit.AppId, roleId, userRole.User.UserId);
        var userRoleResult = await testInit.TeamClient.ListUserRolesAsync(testInit.AppId, userRole.User.UserId);
        Assert.AreEqual(0, userRoleResult.Items.Count);
    }


    [TestMethod]
    public async Task User_already_exists()
    {
        using var testInit = await TestInit.Create();

        // create
        var email = $"{Guid.NewGuid()}@mail.com";
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppId, Roles.AppAdmin.RoleId, email);

        try
        {
            await testInit.TeamClient.AddUserByEmailAsync(testInit.AppId, Roles.AppAdmin.RoleId, email);
            Assert.Fail("AlreadyExistsException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(AlreadyExistsException), ex.ExceptionTypeName);
        }
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

        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppId);
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
        try
        {
            await testInit.AddNewUser(Roles.AppOwner);
            Assert.Fail($"{nameof(UnauthorizedAccessException)} was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(ex.StatusCode, (int)HttpStatusCode.Forbidden);
        }

        // ---------------
        // Check: update
        // ---------------
        try
        {
            await testInit.TeamClient.AddUserAsync(testInit.AppId, Roles.AppOwner.RoleId, adminApiKey.UserId);
            Assert.Fail($"{nameof(UnauthorizedAccessException)} was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(ex.StatusCode, (int)HttpStatusCode.Forbidden);
        }

        // ---------------
        // Check: remove
        // ---------------
        try
        {
            await testInit.TeamClient.RemoveUserAsync(testInit.AppId, Roles.AppOwner.RoleId, ownerApiKey.UserId);
            Assert.Fail($"{nameof(UnauthorizedAccessException)} was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(ex.StatusCode, (int)HttpStatusCode.Forbidden);
        }
    }

    [TestMethod]
    public async Task Owner_should_not_remove_update_himself(bool allowUserMultiRole)
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: allowUserMultiRole);
        var apiKey = await testInit.AddNewBot(Roles.AppOwner);

        // ---------------
        // Check: update
        // ---------------
        try
        {
            await testInit.TeamClient.AddUserAsync(testInit.AppId, Roles.AppAdmin.RoleId, apiKey.UserId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }

        // ---------------
        // Check: remove
        // ---------------
        try
        {
            await testInit.TeamClient.RemoveUserAsync(testInit.AppId, Roles.AppOwner.RoleId, apiKey.UserId);
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    [TestMethod]
    public async Task Owner_should_remove_other()
    {
        using var testInit = await TestInit.Create();
        var ownerUserRole = await testInit.AddNewUser(Roles.AppOwner);
        await testInit.AddNewBot(Roles.AppOwner);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppId, ownerUserRole.Role.RoleId, ownerUserRole.User!.UserId);
    }

    [TestMethod]
    public async Task Multi_roles()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true);
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppId, roleId: Roles.AppReader.RoleId, userId: userRole1.UserId);
        var appRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppId, userId: userRole1.UserId);
        Assert.AreEqual(2, appRoles.TotalCount);
        Assert.AreEqual(2, appRoles.Items.Count);
        Assert.IsTrue(appRoles.Items.Any(x=>x.Role.RoleId== Roles.AppAdmin.RoleId));
        Assert.IsTrue(appRoles.Items.Any(x=>x.Role.RoleId== Roles.AppReader.RoleId));
    }
}