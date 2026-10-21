using System.Net;
using System.Security.Claims;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.ApiClients;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using UserCreateRequest = GrayMint.Authorization.UserManagement.Abstractions.UserCreateRequest;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class TeamControllerTest
{
    [TestMethod]
    public async Task Added_person_shows_by_email_until_their_first_request()
    {
        using var testInit = await TestInit.Create();
        var item = await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId);

        // a person with an account and a name of their own
        var email = TestInit.NewEmail();
        var personApiKey = await testInit.SignUpNewUser(email,
            [new Claim(ClaimTypes.GivenName, "Ada"), new Claim(ClaimTypes.Surname, "Lovelace")],
            setAsCurrent: false);

        // the team that adds the email sees the email only, in the form it would have for a new account,
        // and can't find the person by their name
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId,
            Roles.AppReader.RoleId, email.ToUpperInvariant());
        Assert.AreEqual(email, userRole.User?.Email);
        Assert.IsNull(userRole.User?.FirstName);

        var newEmail = TestInit.NewEmail();
        var newUserRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId,
            Roles.AppReader.RoleId, newEmail.ToUpperInvariant());
        Assert.AreEqual(newEmail, newUserRole.User?.Email);

        var teamUser = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, userRole.UserId);
        Assert.IsNotNull(teamUser.User);
        Assert.IsNull(teamUser.User.FirstName);
        Assert.IsNull(teamUser.User.LastName);
        Assert.IsFalse(teamUser.User.IsEmailVerified);
        var listedUserRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId);
        Assert.IsNull(listedUserRoles.Items.Single(x => x.UserId == userRole.UserId).User?.FirstName);
        Assert.IsEmpty((await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, search: "Ada")).Items);
        Assert.HasCount(1, (await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, search: email)).Items);

        // their first request to the app shows them in full
        var adminAuthorization = testInit.HttpClient.DefaultRequestHeaders.Authorization;
        testInit.SetApiKey(personApiKey);
        await testInit.ItemsClient.GetByPermissionAsync(testInit.AppId, item.ItemId);
        testInit.HttpClient.DefaultRequestHeaders.Authorization = adminAuthorization;

        teamUser = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, userRole.UserId);
        Assert.IsNotNull(teamUser.User);
        Assert.AreEqual("Ada", teamUser.User.FirstName);
        Assert.AreEqual("Lovelace", teamUser.User.LastName);

        // and a role change keeps it so
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppWriter.RoleId, email);
        var listedUserRole = (await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId,
            userId: userRole.UserId)).Items.Single();
        Assert.AreEqual(Roles.AppWriter.RoleId, listedUserRole.Role.RoleId);
        Assert.AreEqual("Ada", listedUserRole.User?.FirstName);
    }

    [TestMethod]
    public async Task Bot_shows_in_full_at_once()
    {
        using var testInit = await TestInit.Create();
        var botName = Guid.NewGuid().ToString();
        await testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppReader.RoleId,
            new TeamAddBotParam { Name = botName });

        var listedUserRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, isBot: true);
        Assert.IsTrue(listedUserRoles.Items.Any(x => x.User?.FirstName == botName));
    }

    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await TestInit.Create();

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId,
            new TeamAddBotParam {
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
        using var testInit = await TestInit.Create(appSettings: new Dictionary<string, string?>
            { { "TeamController:AllowBotAppOwner", "false" } });
        var apiKey = await testInit.AddNewBot(Roles.AppWriter, setAsCurrent: false);
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, apiKey.UserId));
    }


    [TestMethod]
    public async Task Bot_can_not_be_added_if_it_belong_to_alien_resource()
    {
        using var testInit = await TestInit.Create();
        var apiKey1 = await testInit.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        // a second app in the same host; its admin must not be able to add the first app's bot
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
        await testInit.AddNewBot(Roles.AppAdmin, resourceId: app2.AppId);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserByEmailAsync(app2.AppId.ToString(), Roles.AppAdmin.RoleId,
                botUserRole.User!.Email!));

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppAdmin.RoleId,
                botUserRole.User!.UserId));
    }


    [TestMethod]
    public async Task Bot_can_not_be_reset_if_belongs_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create();
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppResourceId,
            userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId);
        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        using var testInit2 = await TestInit.Create();
        await testInit2.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit2.TeamClient.ResetBotApiKeyAsync(botUserRole.User!.UserId));
    }

    [TestMethod]
    public async Task User_of_alien_resource_can_not_be_read()
    {
        using var testInit = await TestInit.Create();
        var memberEmail = TestInit.NewEmail();
        var member = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, memberEmail);

        // a user of a second app only
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
        var alienEmail = TestInit.NewEmail();
        var alien = await testInit.TeamClient.AddUserByEmailAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, alienEmail);

        // the system's readers still find any user
        await testInit.TeamClient.GetUserAsync(testInit.RootResourceId, alien.UserId);

        // the first app's admin finds its own team only; a user out of it answers as no user at all
        await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, member.UserId);
        await testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, memberEmail);
        ApiException[] errors = [
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, alien.UserId)),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, alienEmail)),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, Guid.NewGuid().ToString())),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, TestInit.NewEmail()))
        ];

        foreach (var error in errors) {
            Assert.AreEqual(nameof(NotExistsException), error.ExceptionTypeName);
            Assert.AreEqual(errors[0].StatusCode, error.StatusCode);
            Assert.AreEqual(errors[0].Message, error.Message);
        }
    }

    [TestMethod]
    public async Task Bot_endpoints_tell_nothing_of_users_out_of_reach()
    {
        using var testInit = await TestInit.Create();

        // the first app's person and bot, an id of no one, and an id that is no id at all
        var person = await testInit.AddNewUser(Roles.AppReader);
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        string[] targetIds = [person.UserId, bot.UserId, Guid.NewGuid().ToString(), "not-an-id"];

        // a second app's admin may manage none of them, so each answers alike
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
        await testInit.AddNewBot(Roles.AppAdmin, resourceId: app2.AppId);
        var errors = new List<ApiException>();
        foreach (var targetId in targetIds) {
            errors.Add(await Assert.ThrowsAsync<ApiException>(() => testInit.TeamClient.ResetBotApiKeyAsync(targetId)));
            errors.Add(await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.UpdateBotAsync(targetId, new TeamUpdateBotParam())));
        }

        foreach (var error in errors) {
            Assert.AreEqual((int)HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual(errors[0].ExceptionTypeName, error.ExceptionTypeName);
            Assert.AreEqual(errors[0].Message, error.Message);
        }
    }

    [TestMethod]
    public async Task Bot_endpoints_tell_nothing_of_a_teammates_other_resources()
    {
        using var testInit = await TestInit.Create();

        // two people on the app, one of them on a second app too
        var person = await testInit.AddNewUser(Roles.AppReader);
        var memberElsewhere = await testInit.AddNewUser(Roles.AppReader);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
        await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, memberElsewhere.UserId);

        // the app's admin can't tell them apart by the bot endpoints
        await testInit.AddNewBot(Roles.AppAdmin);
        var errors = new List<ApiException>();
        foreach (var userId in new[] { person.UserId, memberElsewhere.UserId }) {
            errors.Add(await Assert.ThrowsAsync<ApiException>(() => testInit.TeamClient.ResetBotApiKeyAsync(userId)));
            errors.Add(await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.UpdateBotAsync(userId, new TeamUpdateBotParam())));
        }

        foreach (var error in errors) {
            Assert.AreEqual((int)HttpStatusCode.Forbidden, error.StatusCode);
            Assert.AreEqual(errors[0].ExceptionTypeName, error.ExceptionTypeName);
            Assert.AreEqual(errors[0].Message, error.Message);
        }
    }

    [TestMethod]
    public async Task Ids_of_no_one_leave_nothing_in_the_cache()
    {
        using var testInit = await TestInit.Create();
        await testInit.AddNewBot(Roles.AppAdmin);

        // each call names an id of no one, and is refused
        async Task CallWithIdsOfNoOne()
        {
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.ResetBotApiKeyAsync(Guid.NewGuid().ToString()));
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, Guid.NewGuid().ToString()));
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, Guid.NewGuid().ToString()));
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, Guid.NewGuid().ToString()));
        }

        // past the caller's own entries, the cache stays as it was
        await CallWithIdsOfNoOne();
        var count = testInit.CountCacheEntries();
        for (var i = 0; i < 5; i++)
            await CallWithIdsOfNoOne();

        Assert.AreEqual(count, testInit.CountCacheEntries());
    }

    [TestMethod]
    public async Task Bot_of_alien_resource_can_not_be_reset_by_another_form_of_its_id()
    {
        using var testInit = await TestInit.Create();
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var otherFormId = Guid.Parse(bot.UserId).ToString("N").ToUpperInvariant();

        // the app's admin reads the bot's roles by another form of its id while the bot is in its reach
        var adminApiKey = await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: otherFormId);

        // the bot joins a second app, out of that admin's reach
        testInit.SetApiKey(testInit.SystemAdminApiKey);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
        await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, bot.UserId);

        testInit.SetApiKey(adminApiKey);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.ResetBotApiKeyAsync(otherFormId));
    }

    [TestMethod]
    public async Task User_added_by_another_form_of_the_id_gets_the_role()
    {
        using var testInit = await TestInit.Create();
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });

        // the same id in upper case and without hyphens
        var otherFormId = Guid.Parse(bot.UserId).ToString("N").ToUpperInvariant();
        var userRole = await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, otherFormId);
        Assert.AreEqual(bot.UserId, userRole.UserId);
        Assert.AreEqual(Roles.AppReader.RoleId, userRole.Role.RoleId);
    }

    [TestMethod]
    public async Task Owner_can_not_drop_own_owner_role_by_another_form_of_the_id()
    {
        using var testInit = await TestInit.Create();
        var owner = await testInit.AddNewBot(Roles.AppOwner);
        var otherFormId = Guid.Parse(owner.UserId).ToString("N").ToUpperInvariant();
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, otherFormId));
    }

    [TestMethod]
    public async Task Team_answers_hide_internal_fields()
    {
        using var testInit = await TestInit.Create();
        var user = await testInit.UserProvider.Create(new UserCreateRequest {
            Email = TestInit.NewEmail(),
            Description = Guid.NewGuid().ToString(),
            ExData = Guid.NewGuid().ToString()
        });

        var added = await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, user.UserId);
        var listed = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: user.UserId);
        var read = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, user.UserId);
        foreach (var teamUser in new[] { added.User, listed.Items.Single().User, read.User }) {
            Assert.IsNotNull(teamUser);
            Assert.IsNull(teamUser.AuthorizationCode);
            Assert.IsNull(teamUser.Description);
            Assert.IsNull(teamUser.ExData);
        }
    }

    [TestMethod]
    public async Task App_role_can_not_be_added_on_the_system_resource()
    {
        using var testInit = await TestInit.Create();
        var email = TestInit.NewEmail();
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, Roles.AppReader.RoleId, email));

        // refused before an account was made for the email
        Assert.IsNull(await testInit.UserProvider.FindByEmail(email));
    }

    [TestMethod]
    public async Task Role_id_that_is_no_id_lists_no_one()
    {
        using var testInit = await TestInit.Create();
        await testInit.AddNewUser(Roles.AppReader);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, roleId: "not-an-id");
        Assert.HasCount(0, userRoles.Items);
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
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
                userId: userRole.User.UserId);
        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // add to another role
        roleId = Roles.AppReader.RoleId;
        userRole = await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: roleId,
            userId: userRole.User.UserId);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: userRole.User.UserId);
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
    public async Task Admin_can_not_strip_an_owner_by_a_lesser_role()
    {
        using var testInit = await TestInit.Create();
        var owner = await testInit.AddNewUser(Roles.AppOwner);
        Assert.IsNotNull(owner.User?.Email);

        // a lesser role would take the owner's away, which needs the rights of an owner
        await testInit.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, owner.UserId));
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, owner.User.Email));

        testInit.SetApiKey(testInit.SystemAdminApiKey);
        var ownerRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: owner.UserId);
        Assert.AreEqual(Roles.AppOwner.RoleId, ownerRoles.Items.Single().Role.RoleId);
    }

    [TestMethod]
    public async Task Removing_a_person_keeps_their_account()
    {
        using var testInit = await TestInit.Create();

        // a person who has signed up and holds no role, added to the app by their email and removed again
        var email = TestInit.NewEmail();
        var personApiKey = await testInit.SignUpNewUser(email, setAsCurrent: false);
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, email);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, userRole.UserId);
        Assert.IsNotNull(await testInit.UserProvider.FindById(personApiKey.UserId));

        // an account an email add made, never used, goes with its last role
        var unused = await testInit.AddNewUser(Roles.AppReader);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, unused.UserId);
        Assert.IsNull(await testInit.UserProvider.FindById(unused.UserId));
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
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, ownerUserRole.Role.RoleId,
            ownerUserRole.User!.UserId);
    }

    [TestMethod]
    public async Task Multi_roles()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true);
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: Roles.AppReader.RoleId,
            userId: userRole1.UserId);
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
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
                userId: systemAdmin.UserId);
        var userRole = userRoles.Items.Single();
        Assert.AreEqual(Roles.AppReader.RoleId, userRole.Role.RoleId);

        // remove it
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, systemAdmin.UserId);
        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: systemAdmin.UserId);
        userRole = userRoles.Items.SingleOrDefault();
        Assert.IsNull(userRole);
    }
}