using GrayMint.Authorization.Test.MicroServiceTest.Helper;

namespace GrayMint.Authorization.Test.MicroServiceTest.Tests;

[TestClass]
public class ItemAccessTest
{

    [TestMethod]
    public async Task Create_app_by_system()
    {
        using var testInit = await TestInit.Create();
        await testInit.AppsClient.CreateAppAsync();
    }
}

