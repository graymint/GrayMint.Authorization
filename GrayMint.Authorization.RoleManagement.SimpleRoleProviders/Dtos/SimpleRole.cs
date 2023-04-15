using System;
using System.Linq;
using System.Reflection;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;

public class SimpleRole : IRole
{
    public required Guid RoleId { get; init; }
    public required string RoleName { get; init; }
    public required bool IsSystem { get; init; }
    public required string[] Permissions { get; init; }
    public string? Description { get; init; }

    public static SimpleRole[] GetAll(Type type)
    {
        var properties = type
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.PropertyType == typeof(SimpleRole));

        var roles = properties.Select(propertyInfo => (SimpleRole)propertyInfo.GetValue(null)!);
        return roles.ToArray();
    }
}
