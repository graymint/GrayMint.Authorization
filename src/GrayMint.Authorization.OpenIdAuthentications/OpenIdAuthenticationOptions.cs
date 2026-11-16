namespace GrayMint.Authorization.OpenIdAuthentications;

public class OpenIdAuthenticationOptions
{
    public IReadOnlyList<OpenIdProviderOptions> Providers { get; init; } = [];

    // Lets a person who is no user yet become one at their first sign-in. Without it only someone who was
    // made a user before, by their address, can sign in.
    public bool AllowSelfRegister { get; init; }

    // how long an account's user is remembered before it is read again
    public TimeSpan CacheTimeout { get; init; } = TimeSpan.FromMinutes(10);

    // A mistake here would only show at the first request, as tokens that are all refused.
    public void Validate()
    {
        if (Providers.Count == 0)
            throw new InvalidOperationException("No OpenID provider is configured.");

        foreach (var provider in Providers) {
            if (string.IsNullOrWhiteSpace(provider.Name) || provider.Name.Length > OpenIdProviderOptions.MaxNameLength)
                throw new InvalidOperationException(
                    $"An OpenID provider's Name must be set and no longer than {OpenIdProviderOptions.MaxNameLength} characters.");

            var isWebAddress = Uri.TryCreate(provider.Issuer, UriKind.Absolute, out var issuer) &&
                               (issuer.Scheme == Uri.UriSchemeHttps ||
                                (provider.AllowInsecureHttp && issuer.Scheme == Uri.UriSchemeHttp));
            if (!isWebAddress)
                throw new InvalidOperationException(
                    $"The Issuer of the OpenID provider '{provider.Name}' must be an https address. It is '{provider.Issuer}'.");

            if (string.IsNullOrWhiteSpace(provider.Audience))
                throw new InvalidOperationException($"The Audience of the OpenID provider '{provider.Name}' is not set.");

            if (provider.ClientIds.Any(string.IsNullOrWhiteSpace))
                throw new InvalidOperationException($"A ClientId of the OpenID provider '{provider.Name}' is empty.");

            if (provider.Algorithms.Count == 0 || provider.Algorithms.Any(string.IsNullOrWhiteSpace))
                throw new InvalidOperationException(
                    $"The OpenID provider '{provider.Name}' must name at least one algorithm its tokens are signed with.");
        }

        ThrowIfRepeated(Providers.Select(x => x.Name), "The OpenID provider");
        ThrowIfRepeated(Providers.Select(x => x.Issuer), "The OpenID issuer");

        if (CacheTimeout <= TimeSpan.Zero)
            throw new InvalidOperationException("The CacheTimeout of the OpenID authentication must be more than zero.");
    }

    private static void ThrowIfRepeated(IEnumerable<string> names, string what)
    {
        var repeatedName = names.GroupBy(x => x).FirstOrDefault(x => x.Count() > 1)?.Key;
        if (repeatedName != null)
            throw new InvalidOperationException($"{what} '{repeatedName}' is configured more than once.");
    }
}
