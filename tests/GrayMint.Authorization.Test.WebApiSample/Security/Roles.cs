using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers.Security;

namespace GrayMint.Authorization.Test.WebApiSample.Security;

public static class Roles
{
    public static GmRole AppReader { get; } = new() {
        RoleName = nameof(AppReader),
        RoleId = "{C7383857-4513-4FE5-BC0D-6DEC069FCF1E}",
        IsRoot = false,
        Permissions = [nameof(Permissions.AppRead)]
    };

    public static GmRole AppWriter { get; } = new() {
        RoleName = nameof(AppWriter),
        RoleId = "{114FDE8C-55C5-44EE-A008-9069C21CD129}",
        IsRoot = false,
        Permissions = [nameof(Permissions.AppWrite), .. AppReader.Permissions]
    };

    public static GmRole AppAdmin { get; } = new() {
        RoleName = nameof(AppAdmin),
        RoleId = "{30461C33-16C0-4287-BB72-06E8BDA5B43E}",
        IsRoot = false,
        Permissions = [
            RolePermissions.RoleWrite,
            RolePermissions.RoleRead,
            Permissions.AppCreate,
            .. AppWriter.Permissions
        ]
    };

    public static GmRole AppOwner { get; } = new() {
        RoleName = nameof(AppOwner),
        RoleId = "{B1BBCB18-AA16-4F2F-940F-4683308EFD46}",
        IsRoot = false,
        Permissions = [RolePermissions.RoleWriteOwner, .. AppAdmin.Permissions]
    };

    public static GmRole SystemReader { get; } = new() {
        RoleName = nameof(SystemReader),
        RoleId = "{423FDF7C-D973-484C-9064-1167A75F1467}",
        IsRoot = true,
        Permissions = [.. AppReader.Permissions]
    };

    public static GmRole SystemAdmin { get; } = new() {
        RoleName = nameof(SystemAdmin),
        RoleId = "{AC3A840C-1DDF-4D88-890F-6713DD8F0DDE}",
        IsRoot = true,
        Permissions = [.. AppOwner.Permissions]
    };
}