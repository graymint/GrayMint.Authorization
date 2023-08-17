using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

internal class PermissionAuthorizationRequirement : IAuthorizationRequirement
{
    public required string Permission { get; init; }
    public string? ResourceRouteName { get; init; }
    public string? ResourceValuePrefix { get; init; }
}