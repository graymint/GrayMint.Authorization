using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using GrayMint.Authorization.Test.Helper;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.Client;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
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


    [TestMethod]
    public async Task Failed_on_expired_token()
    {
        using var testInit = await TestInit.Create();
        // ReSharper disable StringLiteralTypo
        var expiredIdToken = 
            "eyJraWQiOiJNWHhGY3Ziam9PYlJqMVhIR0EybGdYM1p5dmQweVRGcFpjNG5HUzIxRTJZPSIsImFsZyI6IlJTMjU2In0." +
            "eyJzdWIiOiI3ODY2MjZmMy03ZjA3LTRkN2MtYTA4Ny02MzNiYjIzZDVkOTUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwi" +
            "aXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tXC91cy1lYXN0LTJfd1hEY3FH" +
            "TW42IiwiY29nbml0bzp1c2VybmFtZSI6InVuaXQtdGVzdGVyIiwib3JpZ2luX2p0aSI6ImExZTEwYjViLWQ3YjgtNGMz" +
            "Yy1hN2Y4LWMzZjgzY2I2Y2JkNSIsImF1ZCI6IjJrbnJqdmxiMjVscDFtdnY5Y2ZmM3Z0c2NpIiwiZXZlbnRfaWQiOiIx" +
            "YjEyMjk0Ny1lNTk2LTQ0NWQtOGNjYS1hZWY0NzIyNTI0ZDIiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY5" +
            "OTc4MTk3MiwiZXhwIjoxNjk5ODY4MzcyLCJpYXQiOjE2OTk3ODE5NzIsImp0aSI6IjJkM2RlZjllLTZkMGUtNDk4MS1h" +
            "MGVlLTBiYjc3YzFjZTRhMCIsImVtYWlsIjoidW5pdC10ZXN0ZXJAbG9jYWwifQ.yefAfe6v7A-W4YWR7jS1SRRUBFvUy" +
            "syGtMdkYlKxUB0rqpKQKukhR5-2anrC8VuBRBJrN6vMqHhd25jHs3vCT9-q9KxBXQPrfCmTOKL7-G9tC6a8vhBprgpvp" +
            "kmQ8qiHdtQlpGyEiBwhG1IrMc8OzryhSq8Uq1Y7tdHiuAW_oefdQSlumcToObrn1h32ELqM3QgQ-uM67Jtw8CV_a9IQs" +
            "0Sj5Ur8U1iPo3ojRHuK1_EulVWi-UJtMGRi7r606PvpXHVLGRvZEeNFd8cYiUDghlb3DJWVDCr9lSN0RrQeESZI2sKvn" +
            "1w0zV5EWhKO3Xkpi0NzAFwbyJvXMMGPVZeSSg";
        // ReSharper restore StringLiteralTypo

        await TestUtil.AssertApiException(System.Net.HttpStatusCode.Unauthorized,
            testInit.AuthenticationClient.SignInAsync(new SignInRequest { IdToken = expiredIdToken }));
    }
}