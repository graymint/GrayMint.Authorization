using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GrayMint.Authorization.OpenIdAuthentications;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

// An identity provider that lives in the test: it signs tokens with keys of its own and publishes them at
// its address, which only the test's own handler answers.
public sealed class TestProvider : IDisposable
{
    public const string ServiceAudience = "files.service";
    public const string ClientId = "app";

    private readonly List<RSA> _keys = [];

    // in every key's id, so that no two providers of a test run have a key of the same id
    private readonly string _keyIdPrefix = Guid.NewGuid().ToString("N")[..8];

    public string Name { get; }
    public string Issuer { get; }

    // how often its keys were read
    public int KeyReadCount { get; private set; }

    public TestProvider(string name = "main")
    {
        Name = name;
        Issuer = $"https://{name}.identity.test/";
        AddKey();
    }

    public OpenIdProviderOptions CreateOptions()
    {
        return new OpenIdProviderOptions {
            Name = Name,
            Issuer = Issuer,
            Audience = ServiceAudience,
            ClientIds = [ClientId]
        };
    }

    // a new key, which the provider signs with from now on; the older ones stay published
    public void AddKey()
    {
        _keys.Add(RSA.Create(2048));
    }

    // with the provider's newest key, in the one way it signs unless a test names another
    public SigningCredentials GetSigningCredentials(string algorithm = SecurityAlgorithms.RsaSha256)
    {
        return new SigningCredentials(CreateSecurityKey(_keys.Count - 1), algorithm);
    }

    public string CreateAccessToken(string subject)
    {
        return CreateToken(new TestToken {
            Subject = subject,
            Audience = ServiceAudience,
            Type = OpenIdAuthenticationDefaults.AccessTokenType
        });
    }

    public string CreateIdToken(string subject, string? email)
    {
        return CreateToken(new TestToken {
            Subject = subject,
            Audience = ClientId,
            Type = "JWT",
            Email = email,
            IsEmailVerified = true
        });
    }

    public string CreateToken(TestToken token)
    {
        var claims = new Dictionary<string, object>(token.Claims) { [JwtRegisteredClaimNames.Sub] = token.Subject };
        if (token.Email != null)
            claims[JwtRegisteredClaimNames.Email] = token.Email;

        if (token.IsEmailVerified != null)
            claims["email_verified"] = token.IsEmailVerified.Value;

        if (token.Name != null)
            claims[JwtRegisteredClaimNames.Name] = token.Name;

        var now = DateTime.UtcNow;
        var expires = token.Expires ?? now.AddMinutes(20);
        var descriptor = new SecurityTokenDescriptor {
            Issuer = token.Issuer ?? Issuer,
            Audience = token.Audience,
            TokenType = token.Type,
            Claims = claims,
            IssuedAt = expires < now ? expires.AddMinutes(-20) : now,
            NotBefore = expires < now ? expires.AddMinutes(-20) : now,
            Expires = expires,
            SigningCredentials = token.SigningCredentials ?? GetSigningCredentials()
        };

        foreach (var audience in token.OtherAudiences)
            descriptor.Audiences.Add(audience);

        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    // a token nobody signed, which says so itself
    public string CreateUnsignedAccessToken(string subject)
    {
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new Dictionary<string, object> {
            ["alg"] = "none", ["typ"] = OpenIdAuthenticationDefaults.AccessTokenType
        }));

        var payload = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new Dictionary<string, object> {
            ["iss"] = Issuer,
            ["aud"] = ServiceAudience,
            ["sub"] = subject,
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds()
        }));

        return $"{header}.{payload}.";
    }

    // what the provider answers at its own address; null for an address that is not its own
    public HttpResponseMessage? Answer(Uri address)
    {
        if (address.GetLeftPart(UriPartial.Authority) + "/" != Issuer)
            return null;

        return address.AbsolutePath switch {
            "/.well-known/openid-configuration" => CreateJson(new Dictionary<string, object> {
                ["issuer"] = Issuer,
                ["jwks_uri"] = $"{Issuer}keys"
            }),
            "/keys" => CreateKeys(),
            _ => new HttpResponseMessage(HttpStatusCode.NotFound)
        };
    }

    public void Dispose()
    {
        foreach (var key in _keys)
            key.Dispose();
    }

    private HttpResponseMessage CreateKeys()
    {
        KeyReadCount++;
        var keys = _keys.Select((key, index) => {
            var parameters = key.ExportParameters(false);
            return new Dictionary<string, object> {
                ["kty"] = "RSA",
                ["use"] = "sig",
                ["alg"] = SecurityAlgorithms.RsaSha256,
                ["kid"] = GetKeyId(index),
                ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
                ["e"] = Base64UrlEncoder.Encode(parameters.Exponent)
            };
        }).ToArray();

        return CreateJson(new Dictionary<string, object> { ["keys"] = keys });
    }

    private RsaSecurityKey CreateSecurityKey(int index)
    {
        return new RsaSecurityKey(_keys[index]) { KeyId = GetKeyId(index) };
    }

    private string GetKeyId(int index)
    {
        return $"{_keyIdPrefix}-{index}";
    }

    private static HttpResponseMessage CreateJson(object value)
    {
        return new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json")
        };
    }
}
