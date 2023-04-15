namespace GrayMint.Authorization.Authentications.CognitoAuthentication;

public class CognitoAuthenticationOptions
{
    public string CognitoArn { get; set; } = default!;
    public string CognitoClientId { get; set; } = default!;
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(10);

    public string CognitoRolePrefix { get; set; } = "cognito:";

    public void Validate()
    {
        if (string.IsNullOrEmpty(CognitoArn))
            throw new Exception($"{nameof(CognitoArn)} has not been set in {nameof(CognitoAuthenticationOptions)}.");

        if (string.IsNullOrEmpty(CognitoClientId))
            throw new Exception($"{nameof(CognitoClientId)} has not been set in {nameof(CognitoAuthenticationOptions)}.");
    }
}