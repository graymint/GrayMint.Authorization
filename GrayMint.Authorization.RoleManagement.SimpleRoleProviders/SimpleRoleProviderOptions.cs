using System;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public class SimpleRoleProviderOptions
{
    public SimpleRole[] Roles { get; init; } = Array.Empty<SimpleRole>();
}