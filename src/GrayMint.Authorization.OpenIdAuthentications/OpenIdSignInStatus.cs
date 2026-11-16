namespace GrayMint.Authorization.OpenIdAuthentications;

public enum OpenIdSignInStatus
{
    Succeeded,

    // not an ID token that a provider of this service made for one of its applications
    InvalidToken,

    // the first sign-in of an account ties it to a user by its address, which the provider doesn't vouch for
    EmailNotVerified,

    // nobody with this address is a user, and people can't become one by themselves
    NotRegistered,

    // the user of this address is tied to another account at the provider
    TiedToAnotherAccount,

    UserDisabled
}
