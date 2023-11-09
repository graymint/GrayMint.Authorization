using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Threading.Tasks;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Persistence;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public class SimpleRoleProvider : IRoleProvider
{
    private readonly SimpleRoleDbContext _simpleRoleDbContext;
    private readonly SimpleRoleProviderOptions _simpleRoleProviderOptions;
    private readonly IResourceProvider _resourceProvider;
    private readonly IEnumerable<SimpleRole> _roles;
    private readonly IMemoryCache _memoryCache;
    public string RootResourceId { get; }

    public SimpleRoleProvider(
        SimpleRoleDbContext simpleRoleDbContext,
        IResourceProvider resourceProvider,
        IOptions<SimpleRoleProviderOptions> simpleRoleProviderOptions,
        IMemoryCache memoryCache)
    {
        if (simpleRoleProviderOptions.Value.Roles.GroupBy(x => x.RoleId).Any(g => g.Count() > 1))
            throw new DuplicateNameException("Duplicate RoleId has been found.");

        _simpleRoleDbContext = simpleRoleDbContext;
        _simpleRoleProviderOptions = simpleRoleProviderOptions.Value;
        _memoryCache = memoryCache;
        _resourceProvider = resourceProvider;
        _roles = simpleRoleProviderOptions.Value.Roles;
        RootResourceId = AuthorizationConstants.RootResourceId;
    }

    public async Task<UserRole> AddUserRole(string resourceId, string roleId, string userId)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        var entry = await _simpleRoleDbContext.UserRoles
            .AddAsync(new UserRoleModel
            {
                RoleId = Guid.Parse(roleId),
                UserId = Guid.Parse(userId),
                ResourceId = resourceId
            });

        await _simpleRoleDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
        return entry.Entity.ToDto(_roles);
    }

    public async Task RemoveUserRoles(UserRoleCriteria criteria)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        var userRoles = await _simpleRoleDbContext.UserRoles
            .Where(x =>
                (criteria.RoleId == null || x.RoleId == Guid.Parse(criteria.RoleId)) &&
                (criteria.UserId == null || x.UserId == Guid.Parse(criteria.UserId)) &&
                (criteria.ResourceId == null || x.ResourceId == criteria.ResourceId))
            .ToArrayAsync();

        foreach (var userRole in userRoles)
            AuthorizationCache.ResetUser(_memoryCache, userRole.UserId.ToString().ToLower());

        _simpleRoleDbContext.UserRoles.RemoveRange(userRoles);
        await _simpleRoleDbContext.SaveChangesAsync();
    }

    public Task<Role[]> GetRoles(string resourceId)
    {
        var isRoot = IsRootResource(resourceId);
        var roles = _roles.Where(x => x.IsRoot == isRoot)
            .Select(x => (Role)x)
            .ToArray();

        return Task.FromResult(roles);
    }

    public Task<Role> GetRole(string resourceId, string roleId)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.Single(x => x.RoleId == roleId && x.IsRoot == isRoot);
        return Task.FromResult((Role)role);
    }

    public Task<Role?> FindRoleByName(string resourceId, string roleName)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.SingleOrDefault(x => x.RoleName == roleName && x.IsRoot == isRoot);
        return Task.FromResult((Role?)role);
    }

    public async Task<UserRole[]> GetUserRoles(UserRoleCriteria criteria)
    {
        var res = await GetUserRoles(criteria, 0, int.MaxValue);
        return res.Items.ToArray();
    }

    public async Task<ListResult<UserRole>> GetUserRoles(UserRoleCriteria criteria, int recordIndex, int recordCount)
    {
        if (criteria.UserId != null)
            return await GetUserRolesWithUserFilter(criteria.ResourceId, criteria.UserId, criteria.RoleId,
                recordIndex: recordIndex, recordCount: recordCount);

        await using var trans = await _simpleRoleDbContext.WithNoLockTransaction();
        var query = _simpleRoleDbContext.UserRoles
            .Where(x =>
                (criteria.RoleId == null || x.RoleId == Guid.Parse(criteria.RoleId)) &&
                (criteria.UserId == null || x.UserId == Guid.Parse(criteria.UserId)) &&
                (criteria.ResourceId == null || x.ResourceId == criteria.ResourceId));

        var results = await query
            .OrderBy(x => x.ResourceId)
            .Skip(recordIndex)
            .Take(recordCount)
            .ToArrayAsync();

        var ret = new ListResult<UserRole>
        {
            TotalCount = results.Length < recordCount ? recordIndex + results.Length : await query.LongCountAsync(),
            Items = results.Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    private async Task<ListResult<UserRole>> GetUserRolesWithUserFilter(string? resourceId, string userId,
        string? roleId, int recordIndex, int recordCount)
    {
        var cacheKey = AuthorizationCache.CreateKey(_memoryCache, userId, "user-roles");
        var userRoles = await _memoryCache.GetOrCreateAsync(cacheKey, async entry =>
        {
            await using var trans = await _simpleRoleDbContext.WithNoLockTransaction();
            var res = await _simpleRoleDbContext.UserRoles
                .Where(x => x.UserId == Guid.Parse(userId))
                .ToArrayAsync();

            entry.SetAbsoluteExpiration(_simpleRoleProviderOptions.CacheTimeout);
            return res;
        });

        if (userRoles == null)
            throw new Exception("Role cache has been corrupted.");

        var results = userRoles
            .Where(x =>
                (roleId == null || x.RoleId == Guid.Parse(roleId)) &&
                (resourceId == null || x.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(x => x.ResourceId)
            .Skip(recordIndex)
            .Take(recordCount)
            .ToArray();

        var ret = new ListResult<UserRole>
        {
            TotalCount = results.Length < recordCount ? recordIndex + results.Length : userRoles.LongCount(),
            Items = results.Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    public async Task<string[]> GetUserPermissions(string resourceId, string userId)
    {
        var resource = await _resourceProvider.Get(resourceId);

        // get roles for the resource and system resource
        var userRoles = await GetUserRoles(new UserRoleCriteria { ResourceId = resourceId, UserId = userId });

        // find simple roles
        var roles = _roles.Where(x => userRoles.Any(y => y.Role.RoleId == x.RoleId))
            .DistinctBy(x => x.RoleId);

        // find permissions
        var permissions = roles.SelectMany(x => x.Permissions).ToList();

        // add parent permissions
        if (!IsRootResource(resource.ResourceId) && resource.ParentResourceId != null)
            permissions.AddRange(await GetUserPermissions(resource.ParentResourceId, userId));

        return permissions.Distinct().ToArray();
    }

    public Task<string[]> GetRolePermissions(string resourceId, string roleId)
    {
        var permissions = _roles.Single(x => x.RoleId == roleId).Permissions;
        return Task.FromResult(permissions);
    }

    private bool IsRootResource(string resourceId)
    {
        return resourceId == RootResourceId;
    }
}