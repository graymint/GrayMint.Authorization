namespace GrayMint.Authorization.OpenIdAuthentications.Models;

// Ties an account at a provider to a user. The account is named by the provider's own id of it, which never
// changes, and not by its address, which can change hands.
internal class UserBindingModel
{
    public required string Provider { get; init; }
    public required string Subject { get; init; }
    public required Guid UserId { get; init; }
    public DateTime CreatedTime { get; init; }
}
