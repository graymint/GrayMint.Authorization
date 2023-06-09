﻿using System;
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
            Role = roles.SingleOrDefault(x => x.RoleId == model.RoleId) ?? new SimpleRole
            {
                RoleId = model.RoleId,
                RoleName = $"<{model.RoleId}>",
                IsRoot = false,
                Permissions = Array.Empty<string>()
            }
        };
        return userRole;
    }
}


