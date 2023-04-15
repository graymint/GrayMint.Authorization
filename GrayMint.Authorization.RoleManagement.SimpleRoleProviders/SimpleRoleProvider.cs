using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Persistence;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public class SimpleRoleProvider : IRoleProvider
{
    private readonly SimpleRoleDbContext _simpleRoleDbContext;
    private readonly IEnumerable<SimpleRole> _roles;

    public SimpleRoleProvider(
        SimpleRoleDbContext simpleRoleDbContext,
        IOptions<SimpleRoleProviderOptions> simpleRoleProviderOptions)
    {
        _simpleRoleDbContext = simpleRoleDbContext;
        _roles = simpleRoleProviderOptions.Value.Roles;
    }

    public string GetRootResourceId()
    {
        return SimpleRole.RootResourceId;
    }

    public async Task<IUserRole> AddUser(string resourceId, Guid roleId, Guid userId)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();

        var entry = await _simpleRoleDbContext.UserRoles
            .AddAsync(new Models.UserRoleModel
            {
                RoleId = roleId,
                UserId = userId,
                ResourceId = resourceId,
            });
        await _simpleRoleDbContext.SaveChangesAsync();

        return entry.Entity.ToDto(_roles);
    }

    public async Task RemoveUser(string resourceId, Guid roleId, Guid userId)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        _simpleRoleDbContext.UserRoles.Remove(
            new Models.UserRoleModel
            {
                UserId = userId,
                RoleId = roleId,
                ResourceId = resourceId
            });

        await _simpleRoleDbContext.SaveChangesAsync();
    }

    public Task<IRole[]> GetRoles(string resourceId)
    {
        var isRoot = IsRootResource(resourceId);
        var roles = _roles.Where(x => x.IsRoot == isRoot)
            .Select(x => (IRole)x)
            .ToArray();

        return Task.FromResult(roles);
    }

    public Task<IRole> Get(string resourceId, Guid roleId)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.Single(x => x.RoleId == roleId && x.IsRoot == isRoot);
        return Task.FromResult((IRole)role);
    }

    public Task<IRole?> FindByName(string resourceId, string roleName)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.SingleOrDefault(x => x.RoleName == roleName && x.IsRoot == isRoot);
        return Task.FromResult((IRole?)role);
    }

    public async Task<ListResult<IUserRole>> GetUserRoles(
        string? resourceId = null, Guid? roleId = null, Guid? userId = null,
        int recordIndex = 0, int? recordCount = null)
    {
        recordCount ??= int.MaxValue;

        await using var trans = await _simpleRoleDbContext.WithNoLockTransaction();
        var query = _simpleRoleDbContext.UserRoles
            .Where(x =>
                (roleId == null || x.RoleId == roleId) &&
                (userId == null || x.UserId == userId) &&
                (resourceId == null || x.ResourceId == resourceId));

        var results = await query
            .OrderBy(x => x.ResourceId)
            .Skip(recordIndex)
            .Take(recordCount ?? int.MaxValue)
            .ToArrayAsync();

        var ret = new ListResult<IUserRole>
        {
            TotalCount = results.Length < recordCount ? recordIndex + results.Length : await query.LongCountAsync(),
            Items = results.Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    public async Task<string[]> GetUserPermissions(string resourceId, Guid userId)
    {
        // get roles for the resource and system resource
        var userRoles = (await GetUserRoles(resourceId: resourceId, userId: userId)).Items;
        if (!IsRootResource(resourceId))
            userRoles = userRoles.Concat((await GetUserRoles(resourceId: GetRootResourceId(), userId: userId)).Items);

        // find simple roles
        var roles = _roles.Where(x=> userRoles.Any(y=>y.Role.RoleId == x.RoleId))
            .DistinctBy(x=>x.RoleId);

        // find permissions
        var permissions = roles.SelectMany(x => x.Permissions)
            .Distinct();

        return permissions.ToArray();
    }

    public Task<string[]> GetRolePermissions(string resourceId, Guid roleId)
    {
        var permissions = _roles.Single(x => x.RoleId == roleId).Permissions;
        return Task.FromResult(permissions);
    }

    private bool IsRootResource(string resourceId)
    {
        return resourceId == GetRootResourceId();
    }
}
