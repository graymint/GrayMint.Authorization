using System.Collections.Generic;
using System.Linq;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;

internal static class UserRoleConverter
{
    public static IUserRole ToDto(this UserRoleModel model, IEnumerable<IRole> roles)
    {
        var userRole = new SimpleUserRole
        {
            ResourceId = model.ResourceId,
            UserId = model.UserId,
            Role = roles.Single(x => x.RoleId == model.RoleId)
        };
        return userRole;
    }
}


