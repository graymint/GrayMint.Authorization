using System.Net.Http.Headers;

namespace GrayMint.Authorization.Authentications;

public class AccessTokenInfo
{
    public required string Token { get; init; }
    public required DateTime ExpirationTime { get; init; }
    public required string AuthenticationScheme { get; init; }
    public AuthenticationHeaderValue ToAuthorization() => new (AuthenticationScheme, Token);
}