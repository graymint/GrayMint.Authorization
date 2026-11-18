using System.Net;
using System.Web;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Utils;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

// An authentication endpoint exists only where the service's settings let it work: Google's sign-in needs an identity
// provider named Google, and a user's own API key needs AllowUserApiKey. The rest of the sign-in doesn't depend on them.
[TestClass]
public class AuthenticationActionTest
{
    private const string GooglePaths = "api/authentication/external/google/";
    private const string UserApiKeyPath = "api/authentication/current/reset-api-key";

    [TestMethod]
    public async Task Google_sign_in_where_a_Google_provider_is_set_up()
    {
        using var testInit = await TestInit.Create();
        var googleProvider = testInit.AuthenticationOptions.OpenIdProviders
            .Single(x => x.Name == GrayMintAuthenticationDefaults.GoogleProviderName);

        // Google's page, for the provider's audience as its client id
        var signInUrl = new Uri(await testInit.AuthenticationClient.GetGoogleSignInUrlAsync("csrf-token"));
        Assert.AreEqual("accounts.google.com", signInUrl.Host);
        Assert.AreEqual(googleProvider.Audience, HttpUtility.ParseQueryString(signInUrl.Query)["client_id"]);

        Assert.HasCount(2, ApiPaths(testInit).Where(IsGooglePath).ToArray(), "Both are in the API description.");
    }

    [TestMethod]
    public async Task No_Google_sign_in_without_a_Google_provider()
    {
        // the sample's first provider is its Google one; under another name the service has none
        using var testInit = await TestInit.Create(new Dictionary<string, string?> {
            ["Auth:OpenIdProviders:0:Name"] = "NotGoogle"
        });
        Assert.IsFalse(testInit.AuthenticationOptions.OpenIdProviders
            .Any(x => x.Name == GrayMintAuthenticationDefaults.GoogleProviderName));

        await TestUtil.AssertApiException(HttpStatusCode.NotFound,
            testInit.AuthenticationClient.GetGoogleSignInUrlAsync("csrf-token"));
        await TestUtil.AssertApiException(HttpStatusCode.NotFound,
            testInit.AuthenticationClient.GoogleSignInHandlerAsync());
        Assert.IsFalse(ApiPaths(testInit).Any(IsGooglePath), "Neither is in the API description.");

        // signing up and in stays
        await testInit.SignUpNewUser();
        var user = await testInit.AuthenticationClient.GetCurrentUserAsync();
        Assert.IsFalse(string.IsNullOrEmpty(user.Email));
    }

    [TestMethod]
    public async Task User_api_key_where_allowed()
    {
        using var testInit = await TestInit.Create();
        Assert.IsTrue(testInit.AuthenticationOptions.AllowUserApiKey);
        await testInit.SignUpNewUser();

        var apiKey = await testInit.AuthenticationClient.ResetCurrentUserApiKeyAsync();
        testInit.SetApiKey(apiKey);
        await testInit.AuthenticationClient.GetCurrentUserAsync();

        Assert.Contains(UserApiKeyPath, ApiPaths(testInit), "It is in the API description.");
    }

    [TestMethod]
    public async Task No_user_api_key_where_not_allowed()
    {
        using var testInit = await TestInit.Create(new Dictionary<string, string?> {
            ["Auth:AllowUserApiKey"] = "false"
        });
        Assert.IsFalse(testInit.AuthenticationOptions.AllowUserApiKey);
        await testInit.SignUpNewUser();

        await TestUtil.AssertApiException(HttpStatusCode.NotFound,
            testInit.AuthenticationClient.ResetCurrentUserApiKeyAsync());
        Assert.DoesNotContain(UserApiKeyPath, ApiPaths(testInit), "It isn't in the API description.");

        // a bot's key, which its team gives, doesn't need it
        var bot = await testInit.AddNewBot(Roles.SystemAdmin);
        var botApiKey = await testInit.TeamClient.ResetBotApiKeyAsync(bot.UserId);
        testInit.SetApiKey(botApiKey);
        await testInit.AuthenticationClient.GetCurrentUserAsync();
    }

    private static bool IsGooglePath(string path) =>
        path.StartsWith(GooglePaths, StringComparison.OrdinalIgnoreCase);

    private static IReadOnlyList<string> ApiPaths(TestInit testInit) =>
        testInit.WebApp.Services.GetRequiredService<IApiDescriptionGroupCollectionProvider>()
            .ApiDescriptionGroups.Items
            .SelectMany(x => x.Items)
            .Select(x => x.RelativePath ?? "")
            .ToArray();
}
