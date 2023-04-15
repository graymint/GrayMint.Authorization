using System;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;

internal class UserRoleModel
{
    public string ResourceId { get; set; } = default!;
    public Guid UserId { get; set; } 
    public Guid RoleId { get; set; }
}