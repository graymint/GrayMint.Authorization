using System.Collections.Generic;
using System.Linq;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;

internal static class UserRoleConverter
{
    public static UserRole ToDto(this UserRoleModel model, IEnumerable<Role> roles)
    {
        var userRole = new UserRole
        {
            ResourceId = model.ResourceId,
            UserId = model.UserId,
            Role = roles.SingleOrDefault(x => x.RoleId == model.RoleId) ?? new Role
            {
                RoleId = model.RoleId,
                RoleName = $"<{model.RoleId}>",
                Description = string.Empty,
            }
        };
        return userRole;
    }
}


