using GrayMint.Authorization.Test.MicroServiceTest.Helper;

namespace GrayMint.Authorization.Test.MicroServiceTest;

// Every test class derives from it. A test takes its cancellation token here, once: the TestInit it makes through these
// methods keeps the token and passes it on, so a test method names it only where a call of its requires one.
public abstract class TestBase
{
    public required TestContext TestContext { get; set; }

    protected CancellationToken TestCt => TestContext.CancellationToken;

    protected Task<TestInit> CreateTestInit(Dictionary<string, string?>? appSettings = null,
        string environment = "Development")
    {
        return TestInit.Create(appSettings, environment, TestCt);
    }
}
