using System.Net;
using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.ApiClients;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class AwsCognitoTest
{
    public static async Task<string> GetCredentialsAsync(TestInit testInit, string email, string password)
    {
        // ReSharper disable StringLiteralTypo
        var cognitoArn = Arn.Parse("arn:aws:cognito-idp:us-west-1:462524074877:userpool/us-west-1_YNaOUCR2Z");
        var cognitoClientId = "jqo9dsrijnrq5ikkj9rnlgss3";
        // ReSharper restore StringLiteralTypo

        var awsRegion = RegionEndpoint.GetBySystemName(cognitoArn.Region);
        var provider = new AmazonCognitoIdentityProviderClient(new AnonymousAWSCredentials(), awsRegion);
        var userPool = new CognitoUserPool(cognitoArn.Resource, cognitoClientId, provider);
        var user = new CognitoUser(email, cognitoClientId, userPool, provider);
        var authRequest = new InitiateSrpAuthRequest
        {
            Password = password
        };

        var authResponse = await user.StartWithSrpAuthAsync(authRequest);
        var idToken = authResponse.AuthenticationResult.IdToken;
        return idToken;
    }

    [TestMethod]
    public async Task CognitoTest()
    {
        using var testInit = await TestInit.Create();

        // add user to appCreator role
        try
        {
            await testInit.TeamClient.AddUserByEmailAsync(testInit.RootResourceId, Roles.SystemAdmin.RoleId, "unit-tester@foo.local");
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


    [TestMethod]
    public async Task Failed_on_expired_token()
    {
        using var testInit = await TestInit.Create();

        // ReSharper disable StringLiteralTypo
        var expiredIdToken =
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY4MzNlOGE3ZmUzZmU0Yjg3ODk0ODIxOWExNjg0YWZhMzczY2E4NmYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTMwMjQ4NTUyMzMtbjVzdmhuMWlzMWR0cm1za21qanRzZzM3dXBqY3BwNjAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTMwMjQ4NTUyMzMtbjVzdmhuMWlzMWR0cm1za21qanRzZzM3dXBqY3BwNjAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDkwMDk2MDgxNTg5OTI1Nzg1MjMiLCJlbWFpbCI6Im1hZG5pazdAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoiMTExMTExMTExMTExMTExMTEiLCJuYmYiOjE2OTk4NTIyMTMsIm5hbWUiOiJNb2hhbW1hZCBOaWtyYXZhbiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NJM3lWdzljRmRsTUp4Tk1aRnVBR0tEM1d1Q04zWHdOWTkzVjQxVU53WGFzeEdHPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6Ik1vaGFtbWFkIiwiZmFtaWx5X25hbWUiOiJOaWtyYXZhbiIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjk5ODUyNTEzLCJleHAiOjE2OTk4NTYxMTMsImp0aSI6ImE3NzA1OTllMDM4MzgyODI0YjMyMmI5MGI5OWM0ZmM3NjdjMGNkOWMifQ.i8RZX6zkrnqK7bc8OPGyiCbt5EYs44spvysieJqiUSJ4LK_uf3H0Rk4_ZWwXitByKEVMwjrtsnr9QikjxbKuA7rV93NzwQhLXIx7C5fl97-GcDaufPHJNLvXzFjFKy4FycLBFiYvjy6ctq40OWodQDmO0jqHY-m-n7vgV07z0j59wNPZ36gush7O7kjhqqHhKNXRyX_k6tzLJLFBt4R7JEABYLllL1xmZbpWhY2msMQ8BJaSXvpIbjU8NnHc2ISfatt0ArZxyvQ6RuGVSfSHws6CwyJYzqT5wbIINTeC7ktdM1rY-_HbxZTC09qO0CPazgwvpfsvxvWlWZKs5dqTaw";
        // ReSharper restore StringLiteralTypo

        await TestUtil.AssertApiException(HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = expiredIdToken }));
    }
}