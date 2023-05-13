using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Security;

namespace GrayMint.Authorization.Test.WebApiSample.Security;

public static class Roles
{
    public static SimpleRole AppReader { get; } = new()
    {
        RoleName = nameof(AppReader),
        RoleId = Guid.Parse("{C7383857-4513-4FE5-BC0D-6DEC069FCF1E}"),
        IsRoot = false,
        Permissions = new[]
        {
            nameof(Permissions.ItemRead)
        },
    };

    public static SimpleRole AppWriter { get; } = new()
    {
        RoleName = nameof(AppWriter),
        RoleId = Guid.Parse("{114FDE8C-55C5-44EE-A008-9069C21CD129}"),
        IsRoot = false,
        Permissions = new[]
        {
            nameof(Permissions.ItemWrite),
        }.Concat(AppReader.Permissions).ToArray()
    };

    public static SimpleRole AppAdmin { get; } = new()
    {
        RoleName = nameof(AppAdmin),
        RoleId = Guid.Parse("{30461C33-16C0-4287-BB72-06E8BDA5B43E}"),
        IsRoot = false,
        Permissions = new[]
        {
            RolePermissions.RoleWrite,
            RolePermissions.RoleRead,
        }.Concat(AppWriter.Permissions).ToArray()
    };

    public static SimpleRole AppOwner { get; } = new()
    {
        RoleName = nameof(AppOwner),
        RoleId = Guid.Parse("{B1BBCB18-AA16-4F2F-940F-4683308EFD46}"),
        IsRoot = false,
        Permissions = new[]
        {
            RolePermissions.RoleWriteOwner,
        }.Concat(AppAdmin.Permissions).ToArray()
    };

    public static SimpleRole SystemReader { get; } = new()
    {
        RoleName = nameof(SystemReader),
        RoleId = Guid.Parse("{423FDF7C-D973-484C-9064-1167A75F1467}"),
        IsRoot = true,
        Permissions = new[]
        {
            nameof(Permissions.SystemRead),
        }.Concat(AppReader.Permissions).ToArray()
    };

    public static SimpleRole SystemAdmin { get; } = new()
    {
        RoleName = nameof(SystemAdmin),
        RoleId = Guid.Parse("{AC3A840C-1DDF-4D88-890F-6713DD8F0DDE}"),
        IsRoot = true,
        Permissions = new[]
        {
            nameof(Permissions.SystemWrite),
            nameof(Permissions.SystemRead),
        }.Concat(AppOwner.Permissions).ToArray()
    };

    public static SimpleRole EnterpriseAdmin { get; } = new()
    {
        RoleName = "cognito:Enterprise_Admin",
        RoleId = Guid.Parse("{4D79F619-319B-4787-BCEE-FD0DDF3EE75A}"),
        IsRoot = true,
        Permissions = SystemAdmin.Permissions
    };
}