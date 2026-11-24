using GrayMint.Authorization.Test.WebApiSampleTest.Helper;

namespace GrayMint.Authorization.Test.WebApiSampleTest;

// Every test class derives from it. A test takes its cancellation token here, once: the TestInit it makes through these
// methods keeps the token and passes it on, so a test method names it only where a call of its requires one.
public abstract class TestBase
{
    public required TestContext TestContext { get; set; }

    protected CancellationToken TestCt => TestContext.CancellationToken;

    // createSystemAdmin: false leaves the app without a caller, App, or SystemAdminApiKey;
    // handedOutUsers: the user provider keeps there each user it hands out
    protected Task<TestInit> CreateTestInit(Dictionary<string, string?>? appSettings = null,
        string environment = "Development", bool allowUserMultiRole = false,
        bool useResourceProvider = false, bool createSystemAdmin = true, HandedOutUsers? handedOutUsers = null)
    {
        return TestInit.Create(appSettings, environment, allowUserMultiRole, useResourceProvider, createSystemAdmin,
            handedOutUsers, TestCt);
    }
}
