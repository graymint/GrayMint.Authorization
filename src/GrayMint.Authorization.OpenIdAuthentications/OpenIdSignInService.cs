using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Utils;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.OpenIdAuthentications;

// What an application calls once its person has signed in at the provider, with the ID token it got there.
// It ties the account to its user the first time; from then on the provider's access tokens are that user's.
public sealed class OpenIdSignInService(
    OpenIdIdTokenReader idTokenReader,
    UserBindingStore bindingStore,
    IUserProvider userProvider,
    IOptions<OpenIdAuthenticationOptions> options)
{
    public Task<OpenIdSignInResult> SignIn(string idToken, CancellationToken cancellationToken)
    {
        return SignIn(idToken, options.Value.AllowSelfRegister, cancellationToken);
    }

    // For a service whose people become users at a step of its own, such as a page where they accept its
    // terms: as SignIn, and someone who is no user yet becomes one, whatever AllowSelfRegister says.
    public Task<OpenIdSignInResult> SignUp(string idToken, CancellationToken cancellationToken)
    {
        return SignIn(idToken, isRegisterAllowed: true, cancellationToken);
    }

    private async Task<OpenIdSignInResult> SignIn(string idToken, bool isRegisterAllowed,
        CancellationToken cancellationToken)
    {
        var identity = await idTokenReader.Read(idToken, cancellationToken);
        if (identity == null)
            return Refuse(OpenIdSignInStatus.InvalidToken);

        // someone who came before is found by the provider's id of the account, whatever its address is now
        var userId = await bindingStore.FindUserId(identity.ProviderName, identity.Subject, cancellationToken);
        if (userId != null) {
            var tiedUser = await userProvider.FindById(userId, cancellationToken);
            if (tiedUser != null)
                return Complete(tiedUser);

            // The user is gone, and the tie holds nobody. It is taken away, and the account comes as for
            // the first time: left there, it would keep the person out for good, also once they are made a
            // user again.
            await bindingStore.Remove(identity.ProviderName, identity.Subject, userId, cancellationToken);
        }

        // The first time, the account becomes the user of its address, on the provider's word that the
        // address is the person's. Without that word anyone could make an account there with a user's
        // address and be that user here.
        if (!identity.IsEmailVerified || string.IsNullOrWhiteSpace(identity.Email))
            return Refuse(OpenIdSignInStatus.EmailNotVerified);

        var user = await FindByEmail(identity.Email, cancellationToken);
        if (user == null && !isRegisterAllowed)
            return Refuse(OpenIdSignInStatus.NotRegistered);

        user ??= await Register(identity, identity.Email, cancellationToken);

        // A locked user is tied to nobody. The account that tried while it was locked would be the user's
        // from the day the lock is taken off, whoever else comes then.
        if (user.IsDisabled)
            return Refuse(OpenIdSignInStatus.UserDisabled);

        // Only a user that no account is tied to yet. An address alone ties nobody a second time: the
        // account it named the first time is the user's, and another one with the address is not.
        if (await bindingStore.TryAdd(identity.ProviderName, identity.Subject, user.UserId, cancellationToken))
            return Complete(await TakeName(user, identity, cancellationToken));

        // turned away: by this same account's other sign-in, which is no error, or by another account
        userId = await bindingStore.FindUserId(identity.ProviderName, identity.Subject, cancellationToken);
        return userId == user.UserId
            ? Complete(user)
            : Refuse(OpenIdSignInStatus.TiedToAnotherAccount);
    }

    private static OpenIdSignInResult Complete(User user)
    {
        return user.IsDisabled
            ? Refuse(OpenIdSignInStatus.UserDisabled)
            : new OpenIdSignInResult { Status = OpenIdSignInStatus.Succeeded, User = user };
    }

    // An address is found as it is written, and then in lower case: whoever made the user by hand may have
    // written it so, while the provider keeps the spelling its person chose.
    private async Task<User?> FindByEmail(string email, CancellationToken cancellationToken)
    {
        return await userProvider.FindByEmail(email, cancellationToken) ??
               await userProvider.FindByEmail(email.ToLowerInvariant(), cancellationToken);
    }

    // A user who was made by their address alone has no name. They take the name of the account that is
    // tied to them, once: a name the service gave them, or that they have by now, stays.
    private async Task<User> TakeName(User user, OpenIdIdentity identity, CancellationToken cancellationToken)
    {
        return string.IsNullOrWhiteSpace(user.Name) && !string.IsNullOrWhiteSpace(identity.Name)
            ? await userProvider.Update(user.UserId, new UserUpdateRequest { Name = new Patch<string?>(identity.Name) },
                cancellationToken)
            : user;
    }

    // The user is made with the address in lower case, whatever spelling the provider keeps. A service that
    // looks for a person by an address someone typed finds them then, and makes no second user of them.
    private async Task<User> Register(OpenIdIdentity identity, string email, CancellationToken cancellationToken)
    {
        try {
            return await userProvider.Create(new UserCreateRequest {
                Email = email.ToLowerInvariant(),
                Name = identity.Name,
                IsEmailVerified = true
            }, cancellationToken);
        }
        catch (DbUpdateException) {
            // the person's other sign-in made the user in the same moment, if it is there now
            return await FindByEmail(email,
                cancellationToken) ?? throw new InvalidOperationException("The user could not be made.");
        }
    }

    private static OpenIdSignInResult Refuse(OpenIdSignInStatus status)
    {
        return new OpenIdSignInResult { Status = status };
    }
}
