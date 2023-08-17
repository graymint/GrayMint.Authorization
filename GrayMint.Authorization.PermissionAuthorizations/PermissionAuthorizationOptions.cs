namespace GrayMint.Authorization.PermissionAuthorizations;

public class PermissionAuthorizationOptions
{
    public required string[] Permissions { get; init; }
    public required string? ResourceRouteName { get; init; }
    public required string? ResourceValuePrefix { get; init; }
}