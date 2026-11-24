using System.Net;
using System.Security.Claims;
using GrayMint.Authorization.OpenIdAuthentications;
using GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Utils;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Tests;

// The access tokens a service takes from a provider: only the provider's own, made for this service, of an
// account that is tied to a user.
[TestClass]
public class AccessTokenTest : TestBase
{
    private const string Email = "someone@example.com";
    private const string Subject = "account-1";
    [TestMethod]
    public async Task AccessTokenOfATiedAccountIsItsUsers()
    {
        using var provider = new TestProvider();
        await using var testHost = await CreateTestHost(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email));

        using var response = await testHost.GetMe(provider.CreateAccessToken(Subject));
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.AreEqual(user.UserId, await response.Content.ReadAsStringAsync());
    }

    // Anyone can make an account at a provider. Its token is the provider's own and names this service, and
    // still opens nothing until the account is tied to a user.
    [TestMethod]
    public async Task AccountThatIsTiedToNoUserIsRefused()
    {
        using var provider = new TestProvider();
        await using var testHost = await CreateTestHost(provider);
        await testHost.CreateUser(Email);

        using var response = await testHost.GetMe(provider.CreateAccessToken(Subject));
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);

        // and nobody gets in without a token
        using var noToken = await testHost.Client.GetAsync("/me");
        Assert.AreEqual(HttpStatusCode.Unauthorized, noToken.StatusCode);
    }

    [TestMethod]
    [DataRow("audience")]
    [DataRow("audience with a slash")]
    [DataRow("issuer")]
    [DataRow("expired")]
    [DataRow("algorithm")]
    [DataRow("type")]
    [DataRow("key")]
    [DataRow("unsigned")]
    [DataRow("no token at all")]
    public async Task AccessTokenMustBeTheProvidersOwnForThisService(string what)
    {
        using var provider = new TestProvider();
        using var stranger = new TestProvider("stranger");
        await using var testHost = await CreateTestHost(provider);
        await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email));

        // a good token of the tied account, with one thing wrong
        var good = new TestToken {
            Subject = Subject,
            Audience = TestProvider.ServiceAudience,
            Type = OpenIdAuthenticationDefaults.AccessTokenType
        };

        var accessToken = what switch {
            // made for another service of the same provider
            "audience" => provider.CreateToken(new TestToken { Subject = Subject, Audience = "another.service", Type = good.Type }),
            // another service of the same provider, whose name is this one's with a slash more
            "audience with a slash" => provider.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience + "/", Type = good.Type }),
            "issuer" => provider.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience, Type = good.Type, Issuer = "https://elsewhere.test/" }),
            "expired" => provider.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience, Type = good.Type, Expires = DateTime.UtcNow.AddMinutes(-2) }),
            // signed with the provider's own key, in a way the service was not told the provider signs
            "algorithm" => provider.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience, Type = good.Type, SigningCredentials = provider.GetSigningCredentials(SecurityAlgorithms.RsaSha384) }),
            // an ID token of the provider is signed with the same keys
            "type" => provider.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience, Type = "JWT" }),
            // in the provider's name, by someone else's key
            "key" => stranger.CreateToken(new TestToken { Subject = Subject, Audience = good.Audience, Type = good.Type, Issuer = provider.Issuer }),
            "unsigned" => provider.CreateUnsignedAccessToken(Subject),
            _ => "this is no token"
        };

        using var response = await testHost.GetMe(accessToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);

        // the good one works, so it was that one thing
        using var goodResponse = await testHost.GetMe(provider.CreateToken(good));
        Assert.AreEqual(HttpStatusCode.OK, goodResponse.StatusCode);
    }

    [TestMethod]
    public async Task LockedUserIsRefused()
    {
        using var provider = new TestProvider();
        await using var testHost = await CreateTestHost(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email));
        var accessToken = provider.CreateAccessToken(Subject);
        using var before = await testHost.GetMe(accessToken);
        Assert.AreEqual(HttpStatusCode.OK, before.StatusCode);

        await testHost.UpdateUser(user.UserId, new UserUpdateRequest { IsDisabled = new Patch<bool>(true) });

        using var after = await testHost.GetMe(accessToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // An account stays tied to its user and to nobody else. Once that user is gone, its token doesn't become
    // the token of whoever has an address that it carries.
    [TestMethod]
    public async Task AccountWhoseUserIsGoneIsNobodyElse()
    {
        using var provider = new TestProvider();
        await using var testHost = await CreateTestHost(provider);
        var user = await testHost.CreateUser(Email);
        await testHost.CreateUser("other@example.com");
        await testHost.SignIn(provider.CreateIdToken(Subject, Email));

        await testHost.RemoveUser(user.UserId);

        // the other user's address, under the name a token carries it by and under the one users are found by
        var accessToken = provider.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ServiceAudience,
            Type = OpenIdAuthenticationDefaults.AccessTokenType,
            Email = "other@example.com",
            Claims = new Dictionary<string, object> { [ClaimTypes.Email] = "other@example.com" }
        });

        using var response = await testHost.GetMe(accessToken);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // A provider lists a new key before it signs with it. A token signed with a key the service has not read
    // yet is turned away once, and makes the service read the provider's keys again.
    [TestMethod]
    public async Task TokenSignedWithANewKeyOfTheProviderIsTaken()
    {
        using var provider = new TestProvider();
        await using var testHost = await CreateTestHost(provider);
        await testHost.CreateUser(Email);
        await testHost.SignIn(provider.CreateIdToken(Subject, Email));
        using var before = await testHost.GetMe(provider.CreateAccessToken(Subject));
        Assert.AreEqual(HttpStatusCode.OK, before.StatusCode);

        provider.AddKey();
        var accessToken = provider.CreateAccessToken(Subject);
        var statusCode = HttpStatusCode.Unauthorized;
        for (var i = 0; i < 50 && statusCode != HttpStatusCode.OK; i++) {
            using var response = await testHost.GetMe(accessToken);
            statusCode = response.StatusCode;
            if (statusCode != HttpStatusCode.OK)
                await Task.Delay(100);
        }

        Assert.AreEqual(HttpStatusCode.OK, statusCode);
    }

    // tokens nobody signed must not make the service ask the provider each time
    [TestMethod]
    public async Task TokensOfUnknownKeysDoNotMakeTheServiceReadTheKeysEachTime()
    {
        using var provider = new TestProvider();
        using var stranger = new TestProvider("stranger");
        await using var testHost = await CreateTestHost(provider);
        var forged = stranger.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ServiceAudience,
            Type = OpenIdAuthenticationDefaults.AccessTokenType,
            Issuer = provider.Issuer
        });

        for (var i = 0; i < 20; i++) {
            using var response = await testHost.GetMe(forged);
            Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        // once at the start, and once more for the first unknown key
        await Task.Delay(500);
        Assert.IsLessThanOrEqualTo(2, provider.KeyReadCount);
    }

    // Each provider's tokens are checked by its own keys alone, and its accounts are its own: the same id at
    // two providers is two accounts.
    [TestMethod]
    public async Task EachProvidersTokensAreCheckedByItsOwnKeys()
    {
        using var first = new TestProvider("first");
        using var second = new TestProvider("second");
        await using var testHost = await CreateTestHost(new TestHostOptions { Providers = [first, second] });
        var firstUser = await testHost.CreateUser(Email);
        var secondUser = await testHost.CreateUser("other@example.com");
        await testHost.SignIn(first.CreateIdToken(Subject, Email));
        await testHost.SignIn(second.CreateIdToken(Subject, "other@example.com"));

        using var firstResponse = await testHost.GetMe(first.CreateAccessToken(Subject));
        Assert.AreEqual(firstUser.UserId, await firstResponse.Content.ReadAsStringAsync());
        using var secondResponse = await testHost.GetMe(second.CreateAccessToken(Subject));
        Assert.AreEqual(secondUser.UserId, await secondResponse.Content.ReadAsStringAsync());

        // the first provider signs a token in the second one's name
        var forged = first.CreateToken(new TestToken {
            Subject = Subject,
            Audience = TestProvider.ServiceAudience,
            Type = OpenIdAuthenticationDefaults.AccessTokenType,
            Issuer = second.Issuer
        });

        using var forgedResponse = await testHost.GetMe(forged);
        Assert.AreEqual(HttpStatusCode.Unauthorized, forgedResponse.StatusCode);
    }
}
