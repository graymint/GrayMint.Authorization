using System;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.RoleProviders;

public class RoleProviderOptions
{
    public SimpleRole[] Roles { get; init; } = Array.Empty<SimpleRole>();
    public TimeSpan CacheTimeout { get; init; } = TimeSpan.FromMinutes(60);
}