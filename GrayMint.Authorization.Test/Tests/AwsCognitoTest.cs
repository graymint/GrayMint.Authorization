using System.Net.Http.Headers;
using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using GrayMint.Common.Exceptions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.Tests;

[TestClass]
public class AwsCognitoTest
{
    public async Task<string> GetCredentialsAsync(TestInit testInit, string email, string password)
    {
        var cognitoArn = Arn.Parse(testInit.CognitoAuthenticationOptions.CognitoArn);
        var awsRegion = RegionEndpoint.GetBySystemName(cognitoArn.Region);
        var provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), awsRegion);
        var userPool = new CognitoUserPool(cognitoArn.Resource, testInit.CognitoAuthenticationOptions.CognitoClientId, provider);
        var user = new CognitoUser(email, testInit.CognitoAuthenticationOptions.CognitoClientId, userPool, provider);
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
        using var testInit = await TestInit.Create(useCognito: true);

        // add user to appCreator role
        try
        {
            await testInit.TeamClient.AddUserByEmailAsync(0, Roles.SystemAdmin.RoleId, "unit-tester@local");
        }
        catch (ApiException ex)
        {
            Assert.AreEqual(nameof(AlreadyExistsException), ex.ExceptionTypeName);
        }

        var idToken = await GetCredentialsAsync(testInit, "unit-tester", "Password1@");
        testInit.HttpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, idToken);

        await testInit.AppsClient.ListAsync();
        await testInit.AppsClient.ListAsync();
    }
}