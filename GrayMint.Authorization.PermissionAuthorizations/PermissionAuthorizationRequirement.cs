using Microsoft.AspNetCore.Authorization;

namespace GrayMint.Authorization.PermissionAuthorizations;

public class PermissionAuthorizationRequirement : IAuthorizationRequirement
{
    public required string Permission { get; init; }
    public string? ResourceRoute { get; init; }
}