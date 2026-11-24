using System.Reflection;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;

public class GmRole : Role
{
    public required bool IsRoot { get; init; }
    public required IReadOnlyList<string> Permissions { get; init; }

    public static IReadOnlyList<GmRole> GetAll(Type type)
    {
        var properties = type
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(x => x.PropertyType == typeof(GmRole));

        return properties
            .Select(propertyInfo => propertyInfo.GetValue(null) as GmRole ??
                                    throw new InvalidOperationException(
                                        $"The role {type.Name}.{propertyInfo.Name} has no value."))
            .ToArray();
    }
}