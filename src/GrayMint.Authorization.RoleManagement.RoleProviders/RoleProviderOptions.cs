using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.RoleProviders;

public class RoleProviderOptions
{
    public GmRole[] Roles { get; init; } = [];
    public TimeSpan CacheTimeout { get; init; } = AuthorizationConstants.CacheTimeout;
}