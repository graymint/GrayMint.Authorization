using System.Security.Claims;
using System.Text.Json;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using GrayMint.Common.Test.Api;
using GrayMint.Common.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class CustomerAccessTest
{
    [TestMethod]
    public async Task Get_by_customer_token()
    {
        var testInit = await TestInit.Create();
        var grayMintAuthentication = testInit.Scope.ServiceProvider.GetRequiredService<GrayMintAuthentication>();
        var customerId = 2000;

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(PermissionAuthorization.BuildPermissionClaim(
            $"apps:{testInit.AppId}:customers:{customerId}",
            Permissions.CustomerRead));
        var apiKeyDto = await grayMintAuthentication.CreateApiKey(claimsIdentity);

        // ------
        // **** Check: success
        // ------
        var apiKey = GmUtil.JsonClone<ApiKey>(apiKeyDto,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        testInit.SetApiKey(apiKey);
        await testInit.CustomerClient.GetByCustomerIdAsync(testInit.AppId, customerId);
    }
}