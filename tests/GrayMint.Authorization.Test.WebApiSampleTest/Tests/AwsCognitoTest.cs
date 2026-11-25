using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Utils;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;
using TokenUse = GrayMint.Authorization.Authentications.Dtos.TokenUse;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class AwsCognitoTest : TestBase
{
    private const string TesterEmail = "unit-tester@foo.local";
    private static async Task<string> GetCredentialsAsync(string email, string password)
    {
        // ids, not words to spell-check
        // ReSharper disable StringLiteralTypo
        var cognitoArn = Arn.Parse("arn:aws:cognito-idp:us-west-1:462524074877:userpool/us-west-1_YNaOUCR2Z");
        const string cognitoClientId = "jqo9dsrijnrq5ikkj9rnlgss3";
        // ReSharper restore StringLiteralTypo

        var awsRegion = RegionEndpoint.GetBySystemName(cognitoArn.Region);
        var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), awsRegion);
        var userPool = new CognitoUserPool(cognitoArn.Resource, cognitoClientId, provider);
        var user = new CognitoUser(email, cognitoClientId, userPool, provider);
        var authRequest = new InitiateSrpAuthRequest {
            Password = password
        };

        var authResponse = await user.StartWithSrpAuthAsync(authRequest);
        var idToken = authResponse.AuthenticationResult.IdToken;
        return idToken;
    }

    [TestMethod]
    public async Task CognitoTest()
    {
        using var testInit = await CreateTestInit();

        // the tester is a system admin; a real database keeps them from an earlier run
        var testers = await testInit.TeamClient.ListUserRolesAsync(TestInit.RootResourceId,
            roleId: Roles.SystemAdmin.RoleId, search: TesterEmail);

        if (testers.Items.Count == 0)
            await testInit.TeamClient.AddUserByEmailAsync(TestInit.RootResourceId, Roles.SystemAdmin.RoleId,
                TesterEmail);

        var idToken = await GetCredentialsAsync("unit-tester", "Password1@");
        var apiKey = await testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = idToken });

        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.ListAsync();
    }


    [TestMethod]
    public async Task Failed_on_expired_token()
    {
        using var testInit = await CreateTestInit();
        var email = $"{Guid.NewGuid()}@example.com";
        await testInit.SignUpNewUser(email, setAsCurrent: false);

        // the same user's id tokens, signed by this service: a fresh one signs in, one that ran out an hour ago,
        // past the validation's clock skew, does not
        var claimsIdentity = new ClaimsIdentity([
            new Claim(JwtRegisteredClaimNames.Email, email),
            new Claim(GrayMintClaimTypes.EmailVerified, "true")
        ]);
        var grayMintAuthentication = testInit.Scope.ServiceProvider.GetRequiredService<GrayMintAuthentication>();
        var idToken = await grayMintAuthentication.CreateIdToken(claimsIdentity, cancellationToken: TestCt);
        await testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = idToken.Value });

        var expiredIdToken = await grayMintAuthentication.CreateToken(claimsIdentity, null, TokenUse.Id,
            JwtUtil.UtcNow.AddHours(-1), TestCt);
        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = expiredIdToken.Value }));
    }
}