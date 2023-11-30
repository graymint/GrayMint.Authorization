using System.Reflection;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

public class GmRole : Role
{
    public required bool IsRoot { get; init; }
    public required string[] Permissions { get; init; }

    public static GmRole[] GetAll(Type type)
    {
        var properties = type
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.PropertyType == typeof(GmRole));

        var roles = properties.Select(propertyInfo => (GmRole)propertyInfo.GetValue(null)!);
        return roles.ToArray();
    }
}
