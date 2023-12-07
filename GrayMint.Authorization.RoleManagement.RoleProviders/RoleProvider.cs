using System.Data;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.RoleProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.RoleProviders.Models;
using GrayMint.Authorization.RoleManagement.RoleProviders.Persistence;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.RoleProviders;

public class RoleProvider : IRoleProvider
{
    private readonly RoleDbContext _roleDbContext;
    private readonly RoleProviderOptions _roleProviderOptions;
    private readonly IRoleResourceProvider _roleResourceProvider;
    private readonly IEnumerable<GmRole> _roles;
    private readonly UserAuthorizationCache _userAuthorizationCache;
    public string RootResourceId { get; }

    public RoleProvider(
        RoleDbContext roleDbContext,
        UserAuthorizationCache userAuthorizationCache,
        IRoleResourceProvider roleResourceProvider,
        IOptions<RoleProviderOptions> roleProviderOptions)
    {
        if (roleProviderOptions.Value.Roles.GroupBy(x => x.RoleId).Any(g => g.Count() > 1))
            throw new DuplicateNameException("Duplicate RoleId has been found.");

        _roleDbContext = roleDbContext;
        _roleProviderOptions = roleProviderOptions.Value;
        _userAuthorizationCache = userAuthorizationCache;
        _roleResourceProvider = roleResourceProvider;
        _roles = roleProviderOptions.Value.Roles;
        RootResourceId = AuthorizationConstants.RootResourceId;
    }

    public async Task<UserRole> AddUserRole(string resourceId, string roleId, string userId)
    {
        // validate role
        var role = _roles.Single(x => x.RoleId == roleId);
        if (role.IsRoot && !IsRootResource(resourceId))
            throw new InvalidOperationException($"The role of {role.RoleName} can only be added on the system resource.");

        _roleDbContext.ChangeTracker.Clear();
        var entry = await _roleDbContext.UserRoles
            .AddAsync(new UserRoleModel
            {
                RoleId = Guid.Parse(roleId),
                UserId = Guid.Parse(userId),
                ResourceId = resourceId
            });

        await _roleDbContext.SaveChangesAsync();
        _userAuthorizationCache.ClearUserItems(userId);
        return entry.Entity.ToDto(_roles);
    }

    public async Task RemoveUserRoles(UserRoleCriteria criteria)
    {
        _roleDbContext.ChangeTracker.Clear();
        var userRoles = await _roleDbContext.UserRoles
            .Where(x =>
                (criteria.RoleId == null || x.RoleId == Guid.Parse(criteria.RoleId)) &&
                (criteria.UserId == null || x.UserId == Guid.Parse(criteria.UserId)) &&
                (criteria.ResourceId == null || x.ResourceId == criteria.ResourceId))
            .ToArrayAsync();

        _roleDbContext.UserRoles.RemoveRange(userRoles);
        await _roleDbContext.SaveChangesAsync();

        // Clear cache
        foreach (var userRole in userRoles)
            _userAuthorizationCache.ClearUserItems(userRole.UserId.ToString().ToLower());
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

        await using var trans = await _roleDbContext.WithNoLockTransaction();
        var query = _roleDbContext.UserRoles
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
        var allUserRoles = await _userAuthorizationCache.GetOrCreateRequiredUserItemAsync(userId, "user-roles",
            async entry =>
            {
                await using var trans = await _roleDbContext.WithNoLockTransaction();
                var res = await _roleDbContext.UserRoles
                    .Where(x => x.UserId == Guid.Parse(userId))
                    .ToArrayAsync();

                entry.SetAbsoluteExpiration(_roleProviderOptions.CacheTimeout);
                return res;
            });

        var results = allUserRoles
            .Where(x =>
                (roleId == null || x.RoleId == Guid.Parse(roleId)) &&
                (resourceId == null || x.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(x => x.ResourceId)
            .Skip(recordIndex)
            .Take(recordCount)
            .ToArray();

        var ret = new ListResult<UserRole>
        {
            TotalCount = results.Length < recordCount ? recordIndex + results.Length : allUserRoles.LongCount(),
            Items = results.Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    public async Task<string[]> GetUserPermissions(string resourceId, string userId)
    {
        var permissions = await _userAuthorizationCache.GetOrCreateRequiredUserItemAsync(userId, 
            $"resources:{resourceId}:user-permissions", entry =>
            {
                entry.SetAbsoluteExpiration(_roleProviderOptions.CacheTimeout);
                return GetUserPermissionsInternal(resourceId, userId);
            });

        return permissions;
    }

    private async Task<string[]> GetUserPermissionsInternal(string resourceId, string userId)
    {
        // get roles for the resource and system resource
        var userRoles = await GetUserRoles(new UserRoleCriteria { ResourceId = resourceId, UserId = userId });

        // find roles
        var roles = _roles.Where(x => userRoles.Any(y => y.Role.RoleId == x.RoleId))
            .DistinctBy(x => x.RoleId);

        // find permissions
        var permissions = roles.SelectMany(x => x.Permissions).ToList();

        // add parent permissions
        var parentResourceId = await _roleResourceProvider.GetParentResourceId(resourceId) ?? RootResourceId;
        if (!IsRootResource(resourceId))
            permissions.AddRange(await GetUserPermissions(parentResourceId, userId));

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