using System.Net;
using System.Security.Claims;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Authorization.UserManagement.UserProviders;
using GrayMint.Common.ApiClients;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using UserCreateRequest = GrayMint.Authorization.UserManagement.Abstractions.UserCreateRequest;
using UserUpdateRequest = GrayMint.Authorization.UserManagement.Abstractions.UserUpdateRequest;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class TeamControllerTest(TestContext testContext)
{
    private CancellationToken CancellationToken => testContext.CancellationToken;

    [TestMethod]
    public async Task Added_person_shows_by_email_until_their_first_request()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var item = await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId, cancellationToken: CancellationToken);

        // a person with an account and a name of their own
        var email = TestInit.NewEmail();
        var personApiKey = await testInit.SignUpNewUser(email,
            [new Claim(ClaimTypes.GivenName, "Ada"), new Claim(ClaimTypes.Surname, "Lovelace")],
            setAsCurrent: false);

        // the team that adds the email sees the email only, in the form it would have for a new account,
        // and can't find the person by their name
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId,
            Roles.AppReader.RoleId, email.ToUpperInvariant(), cancellationToken: CancellationToken);

        Assert.AreEqual(email, userRole.User?.Email);
        Assert.IsNull(userRole.User?.FirstName);

        var newEmail = TestInit.NewEmail();
        var newUserRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId,
            Roles.AppReader.RoleId, newEmail.ToUpperInvariant(), cancellationToken: CancellationToken);

        Assert.AreEqual(newEmail, newUserRole.User?.Email);

        var teamUser = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, userRole.UserId, CancellationToken);
        Assert.IsNotNull(teamUser.User);
        Assert.IsNull(teamUser.User.FirstName);
        Assert.IsNull(teamUser.User.LastName);
        Assert.IsFalse(teamUser.User.IsEmailVerified);
        var listedUserRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, cancellationToken: CancellationToken);
        Assert.IsNull(listedUserRoles.Items.Single(x => x.UserId == userRole.UserId).User?.FirstName);
        var foundByName = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, search: "Ada",
            cancellationToken: CancellationToken);

        Assert.IsEmpty(foundByName.Items);
        var foundByEmail = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, search: email,
            cancellationToken: CancellationToken);

        Assert.HasCount(1, foundByEmail.Items);

        // their first request to the app shows them in full
        var adminAuthorization = testInit.HttpClient.DefaultRequestHeaders.Authorization;
        testInit.SetApiKey(personApiKey);
        await testInit.ItemsClient.GetByPermissionAsync(testInit.AppId, item.ItemId, CancellationToken);
        testInit.HttpClient.DefaultRequestHeaders.Authorization = adminAuthorization;

        teamUser = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, userRole.UserId, CancellationToken);
        Assert.IsNotNull(teamUser.User);
        Assert.AreEqual("Ada", teamUser.User.FirstName);
        Assert.AreEqual("Lovelace", teamUser.User.LastName);

        // and a role change keeps it so
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppWriter.RoleId, email, cancellationToken: CancellationToken);
        var listedRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId,
            userId: userRole.UserId, cancellationToken: CancellationToken);

        var listedUserRole = listedRoles.Items.Single();
        Assert.AreEqual(Roles.AppWriter.RoleId, listedUserRole.Role.RoleId);
        Assert.AreEqual("Ada", listedUserRole.User?.FirstName);
    }

    [TestMethod]
    public async Task Bot_shows_in_full_at_once()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var botName = Guid.NewGuid().ToString();
        await testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppReader.RoleId,
            new TeamAddBotParam { Name = botName }, CancellationToken);

        var listedUserRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, isBot: true, cancellationToken: CancellationToken);
        Assert.Contains(x => x.User?.FirstName == botName, listedUserRoles.Items);
    }

    [TestMethod]
    public async Task Bot_create()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        var apiKey = await testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId,
            new TeamAddBotParam {
                Name = Guid.NewGuid().ToString()
            }, CancellationToken);

        testInit.SetApiKey(apiKey);
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId,
            TestInit.NewEmail(), new TeamAddEmailParam(), CancellationToken);
    }

    [TestMethod]
    public async Task Bot_update()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        var apiKey = await testInit.AddNewBot(Roles.AppWriter, false);
        var newName = Guid.NewGuid().ToString();
        var user = await testInit.TeamClient.UpdateBotAsync(apiKey.UserId,
            new TeamUpdateBotParam { Name = new PatchOfString { Value = newName } }, CancellationToken);

        Assert.AreEqual(newName, user.FirstName);

        var userRole = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: apiKey.UserId, cancellationToken: CancellationToken);
        Assert.AreEqual(newName, userRole.Items.SingleOrDefault()?.User?.FirstName);
    }

    [TestMethod]
    public async Task GetUserPermissions_SingleRole()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        await testInit.AddNewBot(Roles.AppReader);
        var permissions = await testInit.TeamClient.ListCurrentUserPermissionsAsync(testInit.AppResourceId, CancellationToken);
        foreach (var permission in Roles.AppReader.Permissions)
            Assert.Contains(permission, permissions);

        Assert.HasCount(Roles.AppReader.Permissions.Length, permissions);
    }

    [TestMethod]
    public async Task GetUserPermissions_MultiRole()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true, cancellationToken: CancellationToken);
        var apiKey = await testInit.AddNewBot(Roles.AppReader, false);
        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId, CancellationToken);
        testInit.SetApiKey(apiKey);

        var permissions = await testInit.TeamClient.ListCurrentUserPermissionsAsync(testInit.AppResourceId, CancellationToken);
        foreach (var permission in Roles.AppReader.Permissions)
            Assert.Contains(permission, permissions);

        foreach (var permission in Roles.AppWriter.Permissions)
            Assert.Contains(permission, permissions);

        Assert.HasCount(Roles.AppReader.Permissions.Union(Roles.AppAdmin.Permissions).Distinct().Count(), permissions);
    }


    [TestMethod]
    public async Task List_Roles()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // ---------
        // List SystemRoles
        // ---------
        var roles = await testInit.TeamClient.ListRolesAsync(testInit.AppResourceId, CancellationToken);
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemAdmin.RoleId));
        Assert.IsTrue(roles.All(x => x.RoleId != Roles.SystemReader.RoleId));
        Assert.Contains(x => x.RoleId == Roles.AppOwner.RoleId, roles);
        Assert.Contains(x => x.RoleId == Roles.AppReader.RoleId, roles);
        Assert.Contains(x => x.RoleId == Roles.AppWriter.RoleId, roles);
    }

    [TestMethod]
    public async Task List_UserApps()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        await testInit.AddNewBot(Roles.AppOwner);
        var apps = await testInit.TeamClient.ListCurrentUserAppsAsync(CancellationToken);
        var appId = testInit.AppId;
        Assert.Contains(x => x.AppId == appId, apps);
    }

    [TestMethod]
    public async Task Bot_can_not_be_created_as_owner()
    {
        using var testInit = await TestInit.Create(
            appSettings: new Dictionary<string, string?> { { "TeamController:AllowBotAppOwner", "false" } }, cancellationToken: CancellationToken);

        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddNewBotAsync(testInit.AppResourceId, Roles.AppOwner.RoleId,
                new TeamAddBotParam { Name = Guid.NewGuid().ToString() }, CancellationToken));
    }

    [TestMethod]
    public async Task Bot_can_not_be_added_to_owners()
    {
        using var testInit = await TestInit.Create(appSettings: new Dictionary<string, string?>
            { { "TeamController:AllowBotAppOwner", "false" } }, cancellationToken: CancellationToken);

        var apiKey = await testInit.AddNewBot(Roles.AppWriter, setAsCurrent: false);
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, apiKey.UserId, CancellationToken));
    }


    [TestMethod]
    public async Task Bot_can_not_be_added_if_it_belong_to_alien_resource()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var apiKey1 = await testInit.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId, cancellationToken: CancellationToken);

        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);
        Assert.IsNotNull(botUserRole.User?.Email);

        // a second app in the same host; its admin must not be able to add the first app's bot
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);
        await testInit.AddNewBot(Roles.AppAdmin, resourceId: app2.AppId);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserByEmailAsync(app2.AppId.ToString(), Roles.AppAdmin.RoleId,
                botUserRole.User.Email, cancellationToken: CancellationToken));

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppAdmin.RoleId,
                botUserRole.User.UserId, CancellationToken));
    }


    [TestMethod]
    public async Task Bot_can_not_be_reset_if_belongs_to_alien_resource()
    {
        using var testInit1 = await TestInit.Create(cancellationToken: CancellationToken);
        var apiKey1 = await testInit1.AddNewBot(Roles.AppAdmin, false);
        var botUserRoles = await testInit1.TeamClient.ListUserRolesAsync(resourceId: testInit1.AppResourceId,
            userId: apiKey1.UserId, roleId: Roles.AppAdmin.RoleId, cancellationToken: CancellationToken);

        var botUserRole = botUserRoles.Items.FirstOrDefault();
        Assert.IsNotNull(botUserRole);

        using var testInit2 = await TestInit.Create(cancellationToken: CancellationToken);
        await testInit2.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit2.TeamClient.ResetBotApiKeyAsync(botUserRole.UserId, CancellationToken));
    }

    [TestMethod]
    public async Task User_of_alien_resource_can_not_be_read()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var memberEmail = TestInit.NewEmail();
        var member = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, memberEmail, cancellationToken: CancellationToken);

        // a user of a second app only
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);
        var alienEmail = TestInit.NewEmail();
        var alien = await testInit.TeamClient.AddUserByEmailAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, alienEmail, cancellationToken: CancellationToken);

        // the system's readers still find any user
        await testInit.TeamClient.GetUserAsync(TestInit.RootResourceId, alien.UserId, CancellationToken);

        // the first app's admin finds its own team only; a user out of it answers as no user at all
        await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, member.UserId, CancellationToken);
        await testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, memberEmail, CancellationToken);
        IReadOnlyList<ApiException> errors = [
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, alien.UserId, CancellationToken)),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, alienEmail, CancellationToken)),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, Guid.NewGuid().ToString(), CancellationToken)),
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, TestInit.NewEmail(), CancellationToken))
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
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // the first app's person and bot, an id of no one, and an id that is no id at all
        var person = await testInit.AddNewUser(Roles.AppReader);
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        IReadOnlyList<string> targetIds = [person.UserId, bot.UserId, Guid.NewGuid().ToString(), "not-an-id"];

        // a second app's admin may manage none of them, so each answers alike
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);
        await testInit.AddNewBot(Roles.AppAdmin, resourceId: app2.AppId);
        var errors = new List<ApiException>();
        foreach (var targetId in targetIds) {
            errors.Add(await Assert.ThrowsAsync<ApiException>(() => testInit.TeamClient.ResetBotApiKeyAsync(targetId, CancellationToken)));
            errors.Add(await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.UpdateBotAsync(targetId, new TeamUpdateBotParam(), CancellationToken)));
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
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // two people on the app, one of them on a second app too
        var person = await testInit.AddNewUser(Roles.AppReader);
        var memberElsewhere = await testInit.AddNewUser(Roles.AppReader);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);
        await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, memberElsewhere.UserId, CancellationToken);

        // the app's admin can't tell them apart by the bot endpoints
        await testInit.AddNewBot(Roles.AppAdmin);
        var errors = new List<ApiException>();
        foreach (var userId in new[] { person.UserId, memberElsewhere.UserId }) {
            errors.Add(await Assert.ThrowsAsync<ApiException>(() => testInit.TeamClient.ResetBotApiKeyAsync(userId, CancellationToken)));
            errors.Add(await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.UpdateBotAsync(userId, new TeamUpdateBotParam(), CancellationToken)));
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
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        await testInit.AddNewBot(Roles.AppAdmin);

        // past the caller's own entries, the cache stays as it was
        await CallWithIdsOfNoOne(testInit, CancellationToken);
        var count = testInit.CountCacheEntries();
        for (var i = 0; i < 5; i++)
            await CallWithIdsOfNoOne(testInit, CancellationToken);

        Assert.AreEqual(count, testInit.CountCacheEntries());
        return;

        // each call names an id of no one, and is refused
        static async Task CallWithIdsOfNoOne(TestInit testInit, CancellationToken cancellationToken)
        {
            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.ResetBotApiKeyAsync(Guid.NewGuid().ToString(), cancellationToken));

            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.GetUserAsync(testInit.AppResourceId, Guid.NewGuid().ToString(), cancellationToken));

            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, Guid.NewGuid().ToString(),
                    cancellationToken));

            await Assert.ThrowsAsync<ApiException>(() =>
                testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId,
                    Guid.NewGuid().ToString(), cancellationToken));
        }
    }

    [TestMethod]
    public async Task Bot_of_alien_resource_can_not_be_reset_by_another_form_of_its_id()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var otherFormId = Guid.Parse(bot.UserId).ToString("N").ToUpperInvariant();

        // the app's admin reads the bot's roles by another form of its id while the bot is in its reach
        var adminApiKey = await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: otherFormId, cancellationToken: CancellationToken);

        // the bot joins a second app, out of that admin's reach
        testInit.SetApiKey(testInit.SystemAdminApiKey);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);
        await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, bot.UserId, CancellationToken);

        testInit.SetApiKey(adminApiKey);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.ResetBotApiKeyAsync(otherFormId, CancellationToken));
    }

    [TestMethod]
    public async Task User_added_by_another_form_of_the_id_gets_the_role()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var app2 = await testInit.AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() }, CancellationToken);

        // the same id in upper case and without hyphens
        var otherFormId = Guid.Parse(bot.UserId).ToString("N").ToUpperInvariant();
        var userRole = await testInit.TeamClient.AddUserAsync(app2.AppId.ToString(), Roles.AppReader.RoleId, otherFormId, CancellationToken);
        Assert.AreEqual(bot.UserId, userRole.UserId);
        Assert.AreEqual(Roles.AppReader.RoleId, userRole.Role.RoleId);
    }

    [TestMethod]
    public async Task Owner_can_not_drop_own_owner_role_by_another_form_of_the_id()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var owner = await testInit.AddNewBot(Roles.AppOwner);
        var otherFormId = Guid.Parse(owner.UserId).ToString("N").ToUpperInvariant();
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, otherFormId, CancellationToken));
    }

    [TestMethod]
    public async Task Team_answers_hide_internal_fields()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var user = await testInit.UserProvider.Create(new UserCreateRequest {
            Email = TestInit.NewEmail(),
            Description = Guid.NewGuid().ToString(),
            ExData = Guid.NewGuid().ToString()
        });

        var added = await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, user.UserId, CancellationToken);
        var listed = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: user.UserId, cancellationToken: CancellationToken);
        var read = await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, user.UserId, CancellationToken);
        foreach (var teamUser in new[] { added.User, listed.Items.Single().User, read.User }) {
            Assert.IsNotNull(teamUser);
            Assert.IsNull(teamUser.AuthorizationCode);
            Assert.IsNull(teamUser.Description);
            Assert.IsNull(teamUser.ExData);
        }
    }

    [TestMethod]
    public async Task Team_answers_leave_the_providers_users_as_they_were()
    {
        var handedOutUsers = new HandedOutUsers();
        using var testInit = await TestInit.Create(handedOutUsers: handedOutUsers, cancellationToken: CancellationToken);

        // a person and a bot with a value in every field an answer may hide, so hiding any of them in place shows
        var email = TestInit.NewEmail();
        var user = await testInit.UserProvider.Create(new UserCreateRequest {
            Email = email,
            Name = Guid.NewGuid().ToString(),
            FirstName = Guid.NewGuid().ToString(),
            LastName = Guid.NewGuid().ToString(),
            PictureUrl = "https://local/picture.png",
            Phone = "+15550100",
            IsDisabled = true,
            IsEmailVerified = true,
            IsPhoneVerified = true,
            Description = Guid.NewGuid().ToString(),
            ExData = Guid.NewGuid().ToString()
        });

        var bot = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        await testInit.UserProvider.Update(bot.UserId, new UserUpdateRequest {
            Description = Guid.NewGuid().ToString(),
            ExData = Guid.NewGuid().ToString()
        });

        var userProvider = testInit.Scope.ServiceProvider.GetRequiredService<UserProvider>();
        await userProvider.UpdateAccessedTime(user.UserId);
        await userProvider.UpdateAccessedTime(bot.UserId);

        // the person hidden on the app's team and in full on the system's, and the bot updated
        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, user.UserId, CancellationToken);
        await testInit.TeamClient.GetUserAsync(testInit.AppResourceId, user.UserId, CancellationToken);
        await testInit.TeamClient.GetUserByEmailAsync(testInit.AppResourceId, email, CancellationToken);
        await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, cancellationToken: CancellationToken);
        await testInit.TeamClient.GetUserAsync(TestInit.RootResourceId, user.UserId, CancellationToken);
        await testInit.TeamClient.UpdateBotAsync(bot.UserId,
            new TeamUpdateBotParam { Name = new PatchOfString { Value = Guid.NewGuid().ToString() } }, CancellationToken);

        Assert.IsNotEmpty(handedOutUsers.GetAll());
        Assert.IsEmpty(handedOutUsers.GetChanged());
    }

    [TestMethod]
    public async Task Team_answers_show_a_bots_last_use_but_not_a_persons()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var item = await testInit.ItemsClient.CreateByPermissionAsync(testInit.AppId, cancellationToken: CancellationToken);

        // a person and a bot of the app, each after a request to it, which shows the person in full
        var email = TestInit.NewEmail();
        var personApiKey = await testInit.SignUpNewUser(email, setAsCurrent: false);
        var person = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, email, cancellationToken: CancellationToken);
        var botApiKey = await testInit.AddNewBot(Roles.AppReader, setAsCurrent: false);
        var adminAuthorization = testInit.HttpClient.DefaultRequestHeaders.Authorization;
        foreach (var apiKey in new[] { personApiKey, botApiKey }) {
            testInit.SetApiKey(apiKey);
            await testInit.ItemsClient.GetByPermissionAsync(testInit.AppId, item.ItemId, CancellationToken);
        }

        testInit.HttpClient.DefaultRequestHeaders.Authorization = adminAuthorization;
        var storedPerson = await testInit.UserProvider.Get(person.UserId);
        Assert.IsNotNull(storedPerson.AccessedTime);

        // the person's last use tells of their other teams too; a bot's is its team's own
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, cancellationToken: CancellationToken);
        var listedPerson = userRoles.Items.Single(x => x.UserId == person.UserId).User;
        Assert.IsNotNull(listedPerson);
        Assert.IsTrue(listedPerson.IsEmailVerified, "The person should show in full.");
        Assert.IsNull(listedPerson.AccessedTime);
        Assert.IsNotNull(userRoles.Items.Single(x => x.UserId == botApiKey.UserId).User?.AccessedTime);

        foreach (var resourceId in new[] { testInit.AppResourceId, TestInit.RootResourceId }) {
            var teamUser = await testInit.TeamClient.GetUserAsync(resourceId, person.UserId, CancellationToken);
            Assert.IsNotNull(teamUser.User);
            Assert.IsNull(teamUser.User.AccessedTime);
        }
    }

    [TestMethod]
    public async Task App_role_can_not_be_added_on_the_system_resource()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var email = TestInit.NewEmail();
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserByEmailAsync(TestInit.RootResourceId, Roles.AppReader.RoleId, email, cancellationToken: CancellationToken));

        // refused before an account was made for the email
        Assert.IsNull(await testInit.UserProvider.FindByEmail(email));
    }

    [TestMethod]
    public async Task Role_id_that_is_no_id_lists_no_one()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        await testInit.AddNewUser(Roles.AppReader);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, roleId: "not-an-id", cancellationToken: CancellationToken);
        Assert.IsEmpty(userRoles.Items);
    }

    [TestMethod]
    public async Task Crud()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // create
        var roleId = Roles.AppAdmin.RoleId;
        var email = $"{Guid.NewGuid()}@mail.com";
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, roleId, email, cancellationToken: CancellationToken);
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // get
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
                userId: userRole.User.UserId, cancellationToken: CancellationToken);

        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // add to another role
        roleId = Roles.AppReader.RoleId;
        userRole = await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: roleId,
            userId: userRole.User.UserId, cancellationToken: CancellationToken);

        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: userRole.User.UserId, cancellationToken: CancellationToken);

        userRole = userRoles.Items.Single();
        Assert.IsNotNull(userRole.User);
        Assert.AreEqual(email, userRole.User.Email);
        Assert.AreEqual(roleId, userRole.Role.RoleId);

        // delete
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, roleId, userRole.User.UserId, CancellationToken);
        var userRoleResult = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId,
            userId: userRole.User.UserId, cancellationToken: CancellationToken);

        Assert.IsEmpty(userRoleResult.Items);
    }


    [TestMethod]
    public async Task User_already_exists()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // create
        var email = $"{Guid.NewGuid()}@mail.com";
        await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, email, cancellationToken: CancellationToken);
        await TestUtil.AssertApiException<AlreadyExistsException>(
            testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, email, cancellationToken: CancellationToken));
    }

    [TestMethod]
    public async Task List_Users()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // create
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        Assert.IsNotNull(userRole1.User);

        var userRole2 = await testInit.AddNewUser(Roles.AppReader);
        Assert.IsNotNull(userRole2.User);

        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, cancellationToken: CancellationToken);
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
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
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
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, adminApiKey.UserId, CancellationToken));

        // ---------------
        // Check: remove
        // ---------------
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, ownerApiKey.UserId, CancellationToken));
    }

    [TestMethod]
    public async Task Admin_can_not_strip_an_owner_by_a_lesser_role()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var owner = await testInit.AddNewUser(Roles.AppOwner);
        Assert.IsNotNull(owner.User?.Email);

        // a lesser role would take the owner's away, which needs the rights of an owner
        await testInit.AddNewBot(Roles.AppAdmin);
        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, owner.UserId, CancellationToken));

        await TestUtil.AssertApiException(HttpStatusCode.Forbidden,
            testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, owner.User.Email, cancellationToken: CancellationToken));

        testInit.SetApiKey(testInit.SystemAdminApiKey);
        var ownerRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: owner.UserId, cancellationToken: CancellationToken);
        Assert.AreEqual(Roles.AppOwner.RoleId, ownerRoles.Items.Single().Role.RoleId);
    }

    [TestMethod]
    public async Task Removing_a_person_keeps_their_account()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        // a person who has signed up and holds no role, added to the app by their email and removed again
        var email = TestInit.NewEmail();
        var personApiKey = await testInit.SignUpNewUser(email, setAsCurrent: false);
        var userRole = await testInit.TeamClient.AddUserByEmailAsync(testInit.AppResourceId, Roles.AppReader.RoleId, email, cancellationToken: CancellationToken);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, userRole.UserId, CancellationToken);
        Assert.IsNotNull(await testInit.UserProvider.FindById(personApiKey.UserId));

        // an account an email add made, never used, goes with its last role
        var unused = await testInit.AddNewUser(Roles.AppReader);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, unused.UserId, CancellationToken);
        Assert.IsNull(await testInit.UserProvider.FindById(unused.UserId));
    }

    [TestMethod]
    public async Task Owner_can_add_or_update_himself_to_other_role_in_MultiRole()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true, cancellationToken: CancellationToken);
        var apiKey = await testInit.AddNewBot(Roles.AppOwner);

        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId, CancellationToken);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId, CancellationToken);
        var userRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: apiKey.UserId, cancellationToken: CancellationToken);
        Assert.AreEqual(1, userRoles.TotalCount);
        Assert.AreEqual(Roles.AppOwner.RoleId, userRoles.Items.Single().Role.RoleId);
    }

    [TestMethod]
    public async Task Owner_should_not_remove_update_his_role()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var apiKey = await testInit.AddNewBot(Roles.AppOwner);

        // ---------------
        // Check: update
        // ---------------
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppAdmin.RoleId, apiKey.UserId, CancellationToken));

        // ---------------
        // Check: remove
        // ---------------
        await TestUtil.AssertApiException<InvalidOperationException>(
            testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppOwner.RoleId, apiKey.UserId, CancellationToken));
    }

    [TestMethod]
    public async Task Owner_should_remove_other()
    {
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);
        var ownerUserRole = await testInit.AddNewUser(Roles.AppOwner);
        await testInit.AddNewBot(Roles.AppOwner);
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, ownerUserRole.Role.RoleId,
            ownerUserRole.UserId, CancellationToken);
    }

    [TestMethod]
    public async Task Multi_roles()
    {
        using var testInit = await TestInit.Create(allowUserMultiRole: true, cancellationToken: CancellationToken);
        var userRole1 = await testInit.AddNewUser(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(resourceId: testInit.AppResourceId, roleId: Roles.AppReader.RoleId,
            userId: userRole1.UserId, cancellationToken: CancellationToken);

        var appRoles = await testInit.TeamClient.ListUserRolesAsync(testInit.AppResourceId, userId: userRole1.UserId, cancellationToken: CancellationToken);
        Assert.AreEqual(2, appRoles.TotalCount);
        Assert.HasCount(2, appRoles.Items);
        Assert.Contains(x => x.Role.RoleId == Roles.AppAdmin.RoleId, appRoles.Items);
        Assert.Contains(x => x.Role.RoleId == Roles.AppReader.RoleId, appRoles.Items);
    }

    [TestMethod]
    public async Task AppAdmin_add_a_root_user_to_his_app()
    {
        // ---------
        // Create
        // ---------
        using var testInit = await TestInit.Create(cancellationToken: CancellationToken);

        var systemAdmin = await testInit.AddNewUser(Roles.SystemAdmin);
        await testInit.AddNewBot(Roles.AppAdmin);
        await testInit.TeamClient.AddUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, systemAdmin.UserId, CancellationToken);
        var userRoles =
            await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
                userId: systemAdmin.UserId, cancellationToken: CancellationToken);

        var userRole = userRoles.Items.Single();
        Assert.AreEqual(Roles.AppReader.RoleId, userRole.Role.RoleId);

        // remove it
        await testInit.TeamClient.RemoveUserAsync(testInit.AppResourceId, Roles.AppReader.RoleId, systemAdmin.UserId, CancellationToken);
        userRoles = await testInit.TeamClient.ListUserRolesAsync(resourceId: testInit.AppResourceId,
            userId: systemAdmin.UserId, cancellationToken: CancellationToken);

        userRole = userRoles.Items.SingleOrDefault();
        Assert.IsNull(userRole);
    }
}