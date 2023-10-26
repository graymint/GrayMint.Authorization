using System.Net.Http.Headers;
using System.Text.Json.Serialization;

namespace GrayMint.Authorization.Authentications;

public class TokenInfo
{
    public required string Token { get; init; }
    public required DateTime ExpirationTime { get; init; }
    public required string AuthenticationScheme { get; init; }

    [JsonIgnore]
    public AuthenticationHeaderValue AuthenticationHeaderValue => new (AuthenticationScheme, Token);

}