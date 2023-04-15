using System;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;

public class SimpleUserRole : IUserRole
{
    public required string ResourceId { get; set; }
    public required Guid UserId { get; set; }
    public required IRole Role { get; set; }
}
