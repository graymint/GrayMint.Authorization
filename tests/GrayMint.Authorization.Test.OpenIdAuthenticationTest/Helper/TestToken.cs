using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

// What a test has its provider write into a token. Left as it is, it is a good token of its kind; a test
// changes the one thing it is about.
public sealed class TestToken
{
    public required string Subject { get; init; }
    public required string Audience { get; init; }

    // whom else the token is meant for, beside Audience
    public IReadOnlyList<string> OtherAudiences { get; init; } = [];
    public required string Type { get; init; }

    // the provider's own, unless a test sets them
    public string? Issuer { get; init; }
    public SigningCredentials? SigningCredentials { get; init; }

    public string? Email { get; init; }
    public bool? IsEmailVerified { get; init; }
    public string? Name { get; init; }
    public DateTime? Expires { get; init; }

    // more claims, by the names the token carries them under
    public IReadOnlyDictionary<string, object> Claims { get; init; } = new Dictionary<string, object>();
}
