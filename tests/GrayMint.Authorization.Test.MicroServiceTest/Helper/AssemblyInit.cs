namespace GrayMint.Authorization.Test.MicroServiceTest.Helper;

[TestClass]
public static class AssemblyInit
{
    // Tests run method-level parallel and each TestInit boots its own host. On a fresh machine
    // (e.g. a CI runner) concurrent boots race on CREATE DATABASE. Boot once, serially, so the
    // database and all provider tables exist before the parallel tests start.
    [AssemblyInitialize]
    public static async Task Init(TestContext _)
    {
        using var testInit = await TestInit.Create();
    }
}
