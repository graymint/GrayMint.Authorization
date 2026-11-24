using GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest;

// Every test class derives from it. A test takes its cancellation token here, once: the host it makes through these
// methods keeps the token and passes it on, so a test method names it only where a call of its requires one.
public abstract class TestBase
{
    public required TestContext TestContext { get; set; }

    protected CancellationToken TestCt => TestContext.CancellationToken;

    protected Task<TestHost> CreateTestHost(TestProvider provider)
    {
        return TestHost.Create(provider, TestCt);
    }

    protected Task<TestHost> CreateTestHost(TestHostOptions options)
    {
        return TestHost.Create(options, TestCt);
    }
}
