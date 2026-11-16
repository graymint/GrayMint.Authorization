using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.OpenIdAuthentications;

public sealed class OpenIdSignInResult
{
    public required OpenIdSignInStatus Status { get; init; }

    // the user, when the sign-in succeeded
    public User? User { get; init; }
}
