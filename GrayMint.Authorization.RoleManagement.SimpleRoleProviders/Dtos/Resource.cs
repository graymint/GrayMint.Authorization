using GrayMint.Authorization.Abstractions;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;

public class Resource
{
    public required string ResourceId { get; set; }
    public string? ParentResourceId { get; set; } = AuthorizationConstants.RootResourceId;
}