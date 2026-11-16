namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

public sealed class TestHostOptions
{
    // the providers whose tokens the service takes; the first is the one most tests use
    public required IReadOnlyList<TestProvider> Providers { get; init; }
    public bool AllowSelfRegister { get; init; }
}
