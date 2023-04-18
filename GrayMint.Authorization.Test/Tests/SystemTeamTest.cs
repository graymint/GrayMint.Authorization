using System.Net;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.WebApiSample.Security;
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

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.AppId, new TeamAddBotParam
        {
            Name = Guid.NewGuid().ToString(),
            RoleId = Roles.AppAdmin.RoleId
        });

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserAsync(testInit.AppId, new TeamAddUserParam
        {
            Email = TestInit.NewEmail(),
            RoleId = Roles.AppAdmin.RoleId
        });
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
        await testInit1.AddNewUser(Roles.AppOwner);
        var apps = await testInit1.TeamClient.ListCurrentUserResourcesAsync();
        Assert.IsTrue(apps.Any(x => x.AppId == testInit1.AppId));
    }

    [TestMethod]
    public async Task Bot_can_not_be_owner()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { { "RoleController:AllowBotAppOwner", "false" } });

        // --------
        // Check: Bot can't be an owner
        // --------
        try
        {
            await testInit.TeamClient.AddNewBotAsync(testInit.AppId, new TeamAddBotParam
            {
                Name = Guid.NewGuid().ToString(),
                RoleId = Roles.AppOwner.RoleId
            });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }
    }

    [TestMethod]
    public async Task Bot_can_not_be_added()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.TeamClient.AddNewBotAsync(testInit1.AppId, new TeamAddBotParam
        {
            Name = Guid.NewGuid().ToString(),
            RoleId = Roles.AppAdmin.RoleId
        });
        var botUserRole = await testInit1.TeamClient.GetUserAsync(testInit1.AppId, apiKey1.UserId);
        Assert.IsNotNull(botUserRole.User);

        using var testInit2 = await TestInit.Create();
        try
        {
            await testInit2.TeamClient.AddUserAsync(testInit2.AppId, new TeamAddUserParam
            {
                Email = botUserRole.User.Email,
                RoleId = Roles.AppAdmin.RoleId
            });
            Assert.Fail("InvalidOperationException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(InvalidOperationException), ex.ExceptionTypeName);
        }

    }


    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await TestInit.Create();

        // create
        var addUserParam = new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.AppAdmin.RoleId
        };
        var userRole = await testInit.TeamClient.AddUserAsync(testInit.AppId, addUserParam);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(addUserParam.Email, userRole.User.Email);
        Assert.AreEqual(addUserParam.RoleId, userRole.Role.RoleId);

        // get
        userRole = await testInit.TeamClient.GetUserAsync(testInit.AppId, userRole.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(addUserParam.Email, userRole.User.Email);
        Assert.AreEqual(addUserParam.RoleId, userRole.Role.RoleId);

        // update 
        var teamUserUpdate = new TeamUpdateUserParam
        {
            RoleId = new PatchOfGuid { Value = Roles.AppReader.RoleId }
        };
        userRole = await testInit.TeamClient.UpdateUserAsync(testInit.AppId, userRole.User.UserId, teamUserUpdate);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(addUserParam.Email, userRole.User.Email);
        Assert.AreEqual(teamUserUpdate.RoleId.Value, userRole.Role.RoleId);

        userRole = await testInit.TeamClient.GetUserAsync(testInit.AppId, userRole.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(addUserParam.Email, userRole.User.Email);
        Assert.AreEqual(teamUserUpdate.RoleId.Value, userRole.Role.RoleId);

        // delete
        await testInit.TeamClient.RemoveUserAsync(testInit.AppId, userRole.User.UserId);
        try
        {
            await testInit.TeamClient.GetUserAsync(testInit.AppId, userRole.User.UserId);
            Assert.Fail("NotExistsException was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(NotExistsException), ex.ExceptionTypeName);
        }
    }


    [TestMethod]
    public async Task User_already_exists()
    {
        using var testInit = await TestInit.Create();

        // create
        var addUserParam = new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.AppAdmin.RoleId
        };
        await testInit.TeamClient.AddUserAsync(testInit.AppId, addUserParam);

        try
        {
            await testInit.TeamClient.AddUserAsync(testInit.AppId, addUserParam);
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
        var userRole1 = await testInit.TeamClient.AddUserAsync(testInit.AppId, new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.AppAdmin.RoleId
        });
        Assert.IsNotNull(userRole1.User);


        var userRole2 = await testInit.TeamClient.AddUserAsync(testInit.AppId, new TeamAddUserParam
        {
            Email = $"{Guid.NewGuid()}@mail.com",
            RoleId = Roles.AppReader.RoleId
        });
        Assert.IsNotNull(userRole2.User);

        var userRoles = await testInit.TeamClient.ListUsersAsync(testInit.AppId);
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
    public async Task Owner_should_not_change_by_admins()
    {
        using var testInit = await TestInit.Create();
        var ownerApiKey = await testInit.AddNewUser(Roles.AppOwner, false);
        var adminApiKey = await testInit.AddNewUser(Roles.AppAdmin);

        // ---------------
        // Check: add
        // ---------------
        try
        {
            await testInit.TeamClient.AddUserAsync(testInit.AppId, new TeamAddUserParam
            {
                Email = $"{Guid.NewGuid()}@mail.com",
                RoleId = Roles.AppOwner.RoleId
            });
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
            await testInit.TeamClient.UpdateUserAsync(testInit.AppId, adminApiKey.UserId, new TeamUpdateUserParam
            {
                RoleId = new PatchOfGuid { Value = Roles.AppOwner.RoleId }
            });
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
            await testInit.TeamClient.RemoveUserAsync(testInit.AppId, ownerApiKey.UserId);
            Assert.Fail($"{nameof(UnauthorizedAccessException)} was expected.");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(ex.StatusCode, (int)HttpStatusCode.Forbidden);
        }
    }

    [TestMethod]
    public async Task Owner_should_not_remove_update_himself()
    {
        using var testInit = await TestInit.Create();
        var apiKey = await testInit.AddNewUser(Roles.AppOwner);

        // ---------------
        // Check: update
        // ---------------
        try
        {
            await testInit.TeamClient.UpdateUserAsync(testInit.AppId, apiKey.UserId, new TeamUpdateUserParam
            {
                RoleId = new PatchOfGuid { Value = Roles.AppAdmin.RoleId }
            });
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
            await testInit.TeamClient.RemoveUserAsync(testInit.AppId, apiKey.UserId);
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
        var owner1ApiKey = await testInit.AddNewUser(Roles.AppOwner, false);
        await testInit.AddNewUser(Roles.AppOwner);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppId, owner1ApiKey.UserId);
    }

}