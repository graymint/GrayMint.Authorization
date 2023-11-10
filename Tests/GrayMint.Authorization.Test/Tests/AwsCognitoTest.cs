using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class AwsCognitoTest
{
    public static async Task<string> GetCredentialsAsync(TestInit testInit, string email, string password)
    {
        var cognitoArn = Arn.Parse(testInit.AuthenticationOptions.CognitoArn);
        var awsRegion = RegionEndpoint.GetBySystemName(cognitoArn.Region);
        var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), awsRegion);
        var userPool = new CognitoUserPool(cognitoArn.Resource, testInit.AuthenticationOptions.CognitoClientId, provider);
        var user = new CognitoUser(email, testInit.AuthenticationOptions.CognitoClientId, userPool, provider);
        var authRequest = new InitiateSrpAuthRequest()
        {
            Password = password
        };

        var authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);
        var accessToken = authResponse.AuthenticationResult.IdToken;
        return accessToken;
    }

    [TestMethod]
    public async Task CognitoTest()
    {
        using var testInit = await TestInit.Create();

        // add user to appCreator role
        try
        {
            await testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, Roles.SystemAdmin.RoleId, "unit-tester@local");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(AlreadyExistsException), ex.ExceptionTypeName);
        }

        var idToken = await GetCredentialsAsync(testInit, "unit-tester", "Password1@");
        var apiKey = await testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = idToken });

        testInit.SetApiKey(apiKey);
        await testInit.AppsClient.ListAsync();
    }
}