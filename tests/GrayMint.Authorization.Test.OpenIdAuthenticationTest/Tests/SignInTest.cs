using System.Net;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.OpenIdAuthentications;
using GrayMint.Authorization.OpenIdAuthentications.Persistence;
using GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Utils;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Tests;

// The sign-in an application makes for its person with the provider's ID token: it ties the account to its
// user the first time, and to nobody a second time.
[TestClass]
public class SignInTest(TestContext testContext)
{
    private const string Email = "someone@example.com";
    private const string Subject = "account-1";
    private const string OtherSubject = "account-2";
    private CancellationToken CancellationToken => testContext.CancellationToken;

    [TestMethod]
    public async Task FirstSignInTiesTheAccountToTheUserOfItsAddress()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.CreateUser("other@example.com");

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);

        // again and again, it is the same user
        var again = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), again.Status);
        Assert.AreEqual(user.UserId, again.UserId);
    }

    // The address is what ties an account the first time, on the provider's word that it is the person's.
    // Without that word anyone could make an account there with a user's address, and be that user here.
    [TestMethod]
    [DataRow(false)]
    [DataRow(null)]
    public async Task AddressThatTheProviderDoesNotVouchForTiesNobody(bool? isEmailVerified)
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        await testHost.CreateUser(Email);

        var signIn = await testHost.SignIn(provider.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ClientId,
            Type = "JWT",
            Email = Email,
            IsEmailVerified = isEmailVerified
        }), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.EmailNotVerified), signIn.Status);
        Assert.IsNull(signIn.UserId);

        using var response = await testHost.GetMe(provider.CreateAccessToken(Subject), CancellationToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [TestMethod]
    public async Task SomeoneWhoIsNoUserIsRefusedUnlessPeopleMayRegister()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var refused = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.NotRegistered), refused.Status);
        using var response = await testHost.GetMe(provider.CreateAccessToken(Subject), CancellationToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);

        // where they may, the first sign-in makes the user, with the address the provider vouched for
        await using var openHost = await TestHost.Create(new TestHostOptions {
            Providers = [provider], AllowSelfRegister = true
        });
        var signIn = await openHost.SignIn(provider.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ClientId,
            Type = "JWT",
            Email = Email,
            IsEmailVerified = true,
            Name = "Someone"
        }), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);

        await using var scope = openHost.Services.CreateAsyncScope();
        var user = await scope.ServiceProvider.GetRequiredService<IUserProvider>().GetByEmail(Email);
        Assert.AreEqual(user.UserId, signIn.UserId);
        Assert.AreEqual("Someone", user.Name);
        Assert.IsTrue(user.IsEmailVerified);

        using var openResponse = await openHost.GetMe(provider.CreateAccessToken(Subject), CancellationToken);
        Assert.AreEqual(user.UserId, await openResponse.Content.ReadAsStringAsync(CancellationToken));
    }

    // An address ties an account only to a user that no account is tied to yet. A second account with a user's
    // address, also one the provider vouches for, is not that user.
    [TestMethod]
    public async Task SecondAccountWithAUsersAddressIsNotThatUser()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(new TestHostOptions {
            Providers = [provider], AllowSelfRegister = true
        });
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);

        var second = await testHost.SignIn(provider.CreateIdToken(OtherSubject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.TiedToAnotherAccount), second.Status);
        Assert.IsNull(second.UserId);
        using var response = await testHost.GetMe(provider.CreateAccessToken(OtherSubject), CancellationToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);

        // the first account is the user still
        using var firstResponse = await testHost.GetMe(provider.CreateAccessToken(Subject), CancellationToken);
        Assert.AreEqual(user.UserId, await firstResponse.Content.ReadAsStringAsync(CancellationToken));
    }

    // Once tied, an account is found by the provider's own id of it. Its address may change there, even to the
    // address of another user: it stays the user it was.
    [TestMethod]
    public async Task TiedAccountIsFoundByItsIdWhateverItsAddressIsNow()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.CreateUser("other@example.com");
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, "other@example.com"), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);

        // and with no address at all
        var noAddress = await testHost.SignIn(provider.CreateIdToken(Subject, email: null), CancellationToken);
        Assert.AreEqual(user.UserId, noAddress.UserId);
    }

    [TestMethod]
    [DataRow("audience")]
    [DataRow("audience with a slash")]
    [DataRow("another application asked")]
    [DataRow("another application asked, for ours alone")]
    [DataRow("several applications, and none asked")]
    [DataRow("access token")]
    [DataRow("issuer")]
    [DataRow("expired")]
    [DataRow("algorithm")]
    [DataRow("key")]
    [DataRow("no token at all")]
    public async Task IdTokenMustBeTheProvidersOwnForOneOfTheServicesApplications(string what)
    {
        using var provider = new TestProvider();
        using var stranger = new TestProvider("stranger");
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);

        var idToken = what switch {
            // made for an application that is not this service's
            "audience" => provider.CreateToken(new TestToken { Subject = Subject, Audience = "another-app", Type = "JWT", Email = Email, IsEmailVerified = true }),
            // another application of the same provider, whose name is ours with a slash more
            "audience with a slash" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId + "/", Type = "JWT", Email = Email, IsEmailVerified = true }),
            // made for another application, which had ours named beside itself
            "another application asked" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, OtherAudiences = ["another-app"], Type = "JWT", Email = Email, IsEmailVerified = true, Claims = new Dictionary<string, object> { ["azp"] = "another-app" } }),
            "another application asked, for ours alone" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = true, Claims = new Dictionary<string, object> { ["azp"] = "another-app" } }),
            // meant for two applications, and it doesn't say which of them asked
            "several applications, and none asked" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, OtherAudiences = ["another-app"], Type = "JWT", Email = Email, IsEmailVerified = true }),
            // an access token that names the application as its audience
            "access token" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = OpenIdAuthenticationDefaults.AccessTokenType, Email = Email, IsEmailVerified = true }),
            "issuer" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = true, Issuer = "https://elsewhere.test/" }),
            "expired" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = true, Expires = DateTime.UtcNow.AddMinutes(-2) }),
            "algorithm" => provider.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = true, SigningCredentials = provider.GetSigningCredentials(Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha384) }),
            "key" => stranger.CreateToken(new TestToken { Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = true, Issuer = provider.Issuer }),
            _ => "this is no token"
        };

        var refused = await testHost.SignIn(idToken, CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.InvalidToken), refused.Status);
        Assert.IsNull(refused.UserId);

        // the good one works, so it was that one thing
        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(user.UserId, signIn.UserId);
    }

    // A token may be meant for more applications than one, and says then which of them asked for it. It is
    // this service's person's when one of this service's applications asked.
    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task IdTokenThatOneOfTheServicesApplicationsAskedForIsTaken(bool isForSeveral)
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);

        var signIn = await testHost.SignIn(provider.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ClientId,
            OtherAudiences = isForSeveral ? ["another-app"] : [],
            Type = "JWT",
            Email = Email,
            IsEmailVerified = true,
            Claims = new Dictionary<string, object> { ["azp"] = TestProvider.ClientId }
        }), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);
    }

    // An account's id is as long as OpenID Connect allows, and no longer: a longer one is refused, not an
    // error of the service.
    [TestMethod]
    public async Task AccountIdIsTakenAsLongAsTheProtocolAllows()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        var longest = new string('a', 255);
        var tooLong = new string('a', 256);

        var refused = await testHost.SignIn(provider.CreateIdToken(tooLong, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.InvalidToken), refused.Status);
        using var refusedResponse = await testHost.GetMe(provider.CreateAccessToken(tooLong), CancellationToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, refusedResponse.StatusCode);

        // it tied nobody: the user is still free for the account of the longest id
        var signIn = await testHost.SignIn(provider.CreateIdToken(longest, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        using var response = await testHost.GetMe(provider.CreateAccessToken(longest), CancellationToken);
        Assert.AreEqual(user.UserId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    // A user that is taken away leaves its account's tie behind. The tie holds nobody, and must not keep the
    // person out once they are made a user again: the account comes as for the first time then.
    [TestMethod]
    public async Task AccountOfAUserThatIsGoneComesAsForTheFirstTime()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var goneUser = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        await using (var scope = testHost.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserProvider>().Remove(goneUser.UserId);

        // nobody has the address now, so the account is nobody's
        var refused = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.NotRegistered), refused.Status);

        // made a user again, the person is tied by the address the provider vouches for, as the first time
        var user = await testHost.CreateUser(Email);
        Assert.AreNotEqual(goneUser.UserId, user.UserId);
        var unverified = await testHost.SignIn(provider.CreateToken(new TestToken {
            Subject = Subject, Audience = TestProvider.ClientId, Type = "JWT", Email = Email, IsEmailVerified = false
        }), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.EmailNotVerified), unverified.Status);

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);
        using var response = await testHost.GetMe(provider.CreateAccessToken(Subject), CancellationToken);
        Assert.AreEqual(user.UserId, await response.Content.ReadAsStringAsync(CancellationToken));
    }

    // Taking away the tie of a user that is gone takes that very tie alone. The account's other sign-in may
    // have tied it to a new user in the same moment, and that tie stays.
    [TestMethod]
    public async Task OnlyTheTieOfTheUserThatIsGoneIsTakenAway()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);

        await using (var scope = testHost.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<UserBindingStore>()
                .Remove(provider.Name, Subject, Guid.CreateVersion7().ToString(), CancellationToken);

        // read anew, and with no address that could tie the account again
        testHost.Services.GetRequiredService<UserAuthorizationCache>().ClearUserItems(user.UserId);
        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, email: null), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);
    }

    // Whoever makes a user by hand may write its address in lower case; the provider keeps the spelling its
    // person chose.
    [TestMethod]
    public async Task UserIsFoundByItsAddressInLowerCaseToo()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, "SomeOne@example.com"), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), signIn.Status);
        Assert.AreEqual(user.UserId, signIn.UserId);
    }

    [TestMethod]
    public async Task LockedUserCanNotSignIn()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await using (var scope = testHost.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserProvider>()
                .Update(user.UserId, new UserUpdateRequest { IsDisabled = new Patch<bool>(true) });

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.UserDisabled), signIn.Status);
        Assert.IsNull(signIn.UserId);

        // The refused sign-in tied nothing: once the lock is off, the user is still free for the account
        // that comes then, and is not the one's that tried while it was locked.
        await using (var scope = testHost.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserProvider>()
                .Update(user.UserId, new UserUpdateRequest { IsDisabled = new Patch<bool>(false) });

        var other = await testHost.SignIn(provider.CreateIdToken(OtherSubject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.Succeeded), other.Status);
        Assert.AreEqual(user.UserId, other.UserId);
    }

    // a user that is locked after its account was tied
    [TestMethod]
    public async Task LockedUserOfATiedAccountCanNotSignIn()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        await using (var scope = testHost.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<IUserProvider>()
                .Update(user.UserId, new UserUpdateRequest { IsDisabled = new Patch<bool>(true) });

        var signIn = await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);
        Assert.AreEqual(nameof(OpenIdSignInStatus.UserDisabled), signIn.Status);
        Assert.IsNull(signIn.UserId);
    }

    // A provider lists a new key before it signs with it. An ID token signed with a key the service has not
    // read yet makes it read the provider's keys again.
    [TestMethod]
    public async Task IdTokenSignedWithANewKeyOfTheProviderIsTaken()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(OtherSubject, "nobody@example.com"), CancellationToken);

        provider.AddKey();
        var idToken = provider.CreateIdToken(Subject, Email);
        var signIn = await testHost.SignIn(idToken, CancellationToken);
        for (var i = 0; i < 50 && signIn.UserId == null; i++) {
            await Task.Delay(100, CancellationToken);
            signIn = await testHost.SignIn(idToken, CancellationToken);
        }

        Assert.AreEqual(user.UserId, signIn.UserId);
    }

    // Of two accounts that come for the same user at the same moment, each finds the user tied to nobody.
    // The table itself lets only one of them in.
    [TestMethod]
    public async Task DatabaseTiesAUserToOneAccount()
    {
        using var provider = new TestProvider();
        await using var testHost = await TestHost.Create(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email), CancellationToken);

        await using var scope = testHost.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<OpenIdDbContext>();
        var userId = Guid.Parse(user.UserId);
        await Assert.ThrowsAsync<DbUpdateException>(() => AddBinding(dbContext, provider.Name, OtherSubject, userId));

        // and one account is one user's
        var otherUser = await testHost.CreateUser("other@example.com");
        dbContext.ChangeTracker.Clear();
        await Assert.ThrowsAsync<DbUpdateException>(() =>
            AddBinding(dbContext, provider.Name, Subject, Guid.Parse(otherUser.UserId)));
    }

    // past the store, which looks before it writes
    private async Task AddBinding(OpenIdDbContext dbContext, string providerName, string subject, Guid userId)
    {
        var bindingType = dbContext.Model.GetEntityTypes().Single().ClrType;
        var binding = Activator.CreateInstance(bindingType) ??
                      throw new InvalidOperationException("The binding could not be made.");
        bindingType.GetProperty("Provider")?.SetValue(binding, providerName);
        bindingType.GetProperty("Subject")?.SetValue(binding, subject);
        bindingType.GetProperty("UserId")?.SetValue(binding, userId);
        dbContext.Add(binding);
        await dbContext.SaveChangesAsync(CancellationToken);
    }
}
