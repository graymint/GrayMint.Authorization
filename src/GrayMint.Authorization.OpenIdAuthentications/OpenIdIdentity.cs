namespace GrayMint.Authorization.OpenIdAuthentications;

// Who a provider's ID token says a person is.
public sealed class OpenIdIdentity
{
    public required string ProviderName { get; init; }

    // the provider's own id of the account, which never changes
    public required string Subject { get; init; }
    public required string? Email { get; init; }
    public required bool IsEmailVerified { get; init; }
    public required string? Name { get; init; }
}
