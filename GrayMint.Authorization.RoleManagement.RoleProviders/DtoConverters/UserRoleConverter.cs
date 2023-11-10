using System;
using System.Collections.Generic;
using System.Linq;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleProviders.Models;

namespace GrayMint.Authorization.RoleManagement.RoleProviders.DtoConverters;

internal static class UserRoleConverter
{
    public static UserRole ToDto(this UserRoleModel model, IEnumerable<Role> roles)
    {
        var modelRoleId = model.RoleId.ToString().ToLower();
        var userRole = new UserRole
        {
            ResourceId = model.ResourceId,
            UserId = model.UserId.ToString().ToLower(),
            Role = roles.SingleOrDefault(x => Guid.TryParse(x.RoleId, out var roleId) && roleId == model.RoleId)
                ?? new Role
                {
                    RoleId = modelRoleId.ToLower(),
                    RoleName = $"<{modelRoleId}>",
                    Description = string.Empty,
                }
        };
        return userRole;
    }
}