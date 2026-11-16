namespace GrayMint.Authorization.OpenIdAuthentications;

// An OpenID Connect identity provider whose tokens the service takes.
public class OpenIdProviderOptions
{
    public const int MaxNameLength = 100;

    // What a user's binding names the provider by. It never changes, and is never given to another issuer:
    // the accounts there would be taken for the users that are bound under the name.
    public required string Name { get; init; }

    // as the provider's tokens carry it, to the last slash
    public required string Issuer { get; init; }

    // the name this service has at the provider: an access token must be meant for it
    public required string Audience { get; init; }

    // The applications whose people sign in to this service: an ID token must be meant for one of them, and
    // asked for by one of them where it says who asked.
    public IReadOnlyList<string> ClientIds { get; init; } = [];

    // the ways the provider signs; a token signed in any other way is refused, whatever its key allows
    public IReadOnlyList<string> Algorithms { get; init; } = ["RS256"];

    // for a developer's machine, where the provider is reached over plain http
    public bool AllowInsecureHttp { get; init; }
}
