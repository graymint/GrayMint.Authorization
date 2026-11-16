namespace GrayMint.Authorization.OpenIdAuthentications;

public static class OpenIdAuthenticationDefaults
{
    // the scheme a service names; it hands each request to the scheme of the provider its token names
    public const string AuthenticationScheme = "GrayMintOpenId";

    // what an access token says it is (RFC 9068), which an ID token never does
    public const string AccessTokenType = "at+jwt";

    public static string GetProviderScheme(string providerName)
    {
        return $"{AuthenticationScheme}:{providerName}";
    }
}
