namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

public sealed class TestSignInResponse
{
    public required string Status { get; init; }
    public string? UserId { get; init; }
}
