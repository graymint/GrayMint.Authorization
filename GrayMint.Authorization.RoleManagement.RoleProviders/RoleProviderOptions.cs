using System;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.RoleProviders;

public class RoleProviderOptions
{
    public GmRole[] Roles { get; init; } = Array.Empty<GmRole>();
    public TimeSpan CacheTimeout { get; init; } = TimeSpan.FromMinutes(60);
}