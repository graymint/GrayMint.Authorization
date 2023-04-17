namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class RoleAuthorizationOptions
{
    public string ResourceParamName { get; set; } = "appId";
    public required string[] AuthenticationSchemes { get; set; }
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(15);
}