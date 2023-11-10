using System;
using System.Linq;
using System.Reflection;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

public class SimpleRole : Role
{
    public required bool IsRoot { get; init; }
    public required string[] Permissions { get; init; }

    public static SimpleRole[] GetAll(Type type)
    {
        var properties = type
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.PropertyType == typeof(SimpleRole));

        var roles = properties.Select(propertyInfo => (SimpleRole)propertyInfo.GetValue(null)!);
        return roles.ToArray();
    }
}
