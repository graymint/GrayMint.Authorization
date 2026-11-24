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

    public async Task<UserRole> AddUserRole(string resourceId, string roleId, string userId,
        CancellationToken cancellationToken)
    {
        // a system role is for the system resource alone, and a resource's role there would apply to every resource
        var role = _roles.Single(x => x.RoleId == roleId);
        if (role.IsRoot != IsRootResource(resourceId))
            throw new InvalidOperationException(role.IsRoot
                ? $"The role of {role.RoleName} can only be added on the system resource."
                : $"The role of {role.RoleName} can not be added on the system resource.");

        // a member who has used the resource stays confirmed when their role changes
        var userGuid = Guid.Parse(userId);
        var userRoleModels = await GetUserRoleModels(userGuid, userId, cancellationToken);
        var confirmedTime = userRoleModels
            .Where(x => x.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase))
            .Max(x => x.ConfirmedTime);

        _roleDbContext.ChangeTracker.Clear();
        var entry = await _roleDbContext.UserRoles
            .AddAsync(new UserRoleModel {
                RoleId = Guid.Parse(roleId),
                UserId = userGuid,
                ResourceId = resourceId,
                ConfirmedTime = confirmedTime
            }, cancellationToken);

        await _roleDbContext.SaveChangesAsync(cancellationToken);
        _userAuthorizationCache.ClearUserItems(userId);
        return entry.Entity.ToDto(_roles);
    }

    public async Task RemoveUserRoles(UserRoleCriteria criteria, CancellationToken cancellationToken)
    {
        // no criterion at all would match every role of every user
        if (criteria is { RoleId: null, UserId: null, ResourceId: null })
            throw new ArgumentException("Removing user roles needs at least one criterion.", nameof(criteria));

        _roleDbContext.ChangeTracker.Clear();
        var userRoles = await _roleDbContext.UserRoles
            .Where(x =>
                (criteria.RoleId == null || x.RoleId == Guid.Parse(criteria.RoleId)) &&
                (criteria.UserId == null || x.UserId == Guid.Parse(criteria.UserId)) &&
                (criteria.ResourceId == null || x.ResourceId == criteria.ResourceId))
            .ToArrayAsync(cancellationToken);

        _roleDbContext.UserRoles.RemoveRange(userRoles);
        await _roleDbContext.SaveChangesAsync(cancellationToken);

        foreach (var userRole in userRoles)
            _userAuthorizationCache.ClearUserItems(userRole.UserId.ToString());
    }

    public Task<IReadOnlyList<Role>> GetRoles(string resourceId)
    {
        var isRoot = IsRootResource(resourceId);
        IReadOnlyList<Role> roles = _roles.Where(x => x.IsRoot == isRoot)
            .Select(Role (x) => x)
            .ToArray();

        return Task.FromResult(roles);
    }

    public Task<Role> GetRole(string resourceId, string roleId)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.Single(x => x.RoleId == roleId && x.IsRoot == isRoot);
        return Task.FromResult<Role>(role);
    }

    public Task<Role?> FindRoleByName(string resourceId, string roleName)
    {
        var isRoot = IsRootResource(resourceId);
        var role = _roles.SingleOrDefault(x => x.RoleName == roleName && x.IsRoot == isRoot);
        return Task.FromResult<Role?>(role);
    }

    public async Task<IReadOnlyList<UserRole>> GetUserRoles(UserRoleCriteria criteria,
        CancellationToken cancellationToken)
    {
        var res = await GetUserRoles(criteria, 0, int.MaxValue, cancellationToken);
        return [.. res.Items];
    }

    public async Task<ListResult<UserRole>> GetUserRoles(UserRoleCriteria criteria, int recordIndex, int recordCount,
        CancellationToken cancellationToken)
    {
        if (criteria.UserId != null)
            return await GetUserRolesWithUserFilter(criteria.ResourceId, criteria.UserId, criteria.RoleId,
                recordIndex: recordIndex, recordCount: recordCount, cancellationToken: cancellationToken);

        // a role id that is no Guid matches no one
        Guid? roleGuid = Guid.TryParse(criteria.RoleId, out var parsedRoleId) ? parsedRoleId : null;
        if (criteria.RoleId != null && roleGuid == null)
            return new ListResult<UserRole> { TotalCount = 0, Items = [] };

        await using var trans = await _roleDbContext.WithNoLockTransaction(cancellationToken);
        var query = _roleDbContext.UserRoles
            .Where(x =>
                (roleGuid == null || x.RoleId == roleGuid) &&
                (criteria.ResourceId == null || x.ResourceId == criteria.ResourceId));

        var results = await query
            .OrderBy(x => x.ResourceId)
            .Skip(recordIndex)
            .Take(recordCount)
            .ToArrayAsync(cancellationToken);

        var ret = new ListResult<UserRole> {
            TotalCount = results.Length < recordCount
                ? recordIndex + results.Length
                : await query.CountAsync(cancellationToken),
            Items = results.Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    private async Task<ListResult<UserRole>> GetUserRolesWithUserFilter(string? resourceId, string userId,
        string? roleId, int recordIndex, int recordCount, CancellationToken cancellationToken)
    {
        // an id that is no Guid belongs to no one, so it answers as an unknown user does
        if (!Guid.TryParse(userId, out var userGuid))
            return new ListResult<UserRole> { TotalCount = 0, Items = [] };

        var userRoleModels = await GetUserRoleModels(userGuid, userId, cancellationToken);
        var userRoles = userRoleModels
            .Where(x =>
                (roleId == null || (Guid.TryParse(roleId, out var roleGuid) && x.RoleId == roleGuid)) &&
                (resourceId == null || x.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(x => x.ResourceId)
            .ToArray();

        var ret = new ListResult<UserRole> {
            TotalCount = userRoles.Length,
            Items = userRoles.Skip(recordIndex).Take(recordCount).Select(x => x.ToDto(_roles)).ToArray()
        };

        return ret;
    }

    // all of a user's roles, cached as they are read; none is kept only for a user the cache already holds, such
    // as the request's own, so a user without roles costs no read per request while ids of no one leave nothing
    private Task<IReadOnlyList<UserRoleModel>> GetUserRoleModels(Guid userGuid, string userId,
        CancellationToken cancellationToken)
    {
        return _userAuthorizationCache.GetOrCreateRequiredUserItemAsync<IReadOnlyList<UserRoleModel>>(userId,
            "user-roles", async entry => {
                await using var trans = await _roleDbContext.WithNoLockTransaction(cancellationToken);
                var res = await _roleDbContext.UserRoles
                    .Where(x => x.UserId == userGuid)
                    .ToArrayAsync(cancellationToken);

                entry.SetAbsoluteExpiration(_roleProviderOptions.CacheTimeout);
                if (res.Length == 0)
                    UserAuthorizationCache.RefuseEntryForUncachedUser(entry);

                return res;
            });
    }

    // the first request a member makes to the resource; written once, as the cached roles take it too
    private async Task ConfirmUserRoles(string resourceId, string userId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(userId, out var userGuid))
            return;

        var cachedUserRoleModels = await GetUserRoleModels(userGuid, userId, cancellationToken);
        var userRoleModels = cachedUserRoleModels
            .Where(x => x.ConfirmedTime == null && x.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (userRoleModels.Length == 0)
            return;

        var confirmedTime = DateTime.UtcNow;
        var userRoleIds = userRoleModels.Select(x => x.UserRoleId).ToArray();
        // Enumerable's Contains, as C# 14 binds an array's to the span overload
        await _roleDbContext.UserRoles
            .Where(x => Enumerable.Contains(userRoleIds, x.UserRoleId) && x.ConfirmedTime == null)
            .ExecuteUpdateAsync(setters => setters.SetProperty(x => x.ConfirmedTime, confirmedTime), cancellationToken);

        foreach (var userRoleModel in userRoleModels)
            userRoleModel.ConfirmedTime = confirmedTime;
    }

    public async Task<IReadOnlyList<string>> GetUserPermissions(string resourceId, string userId,
        CancellationToken cancellationToken)
    {
        var permissions = await _userAuthorizationCache.GetOrCreateRequiredUserItemAsync(userId,
            $"resources:{resourceId}:user-permissions", async entry => {
                entry.SetAbsoluteExpiration(_roleProviderOptions.CacheTimeout);
                var res = await GetUserPermissionsInternal(resourceId, userId, cancellationToken);

                // an empty set isn't kept, so made-up resource ids can't grow the cache
                if (res.Count == 0)
                    UserAuthorizationCache.RefuseEntry(entry);

                return res;
            });

        return permissions;
    }

    private async Task<IReadOnlyList<string>> GetUserPermissionsInternal(string resourceId, string userId,
        CancellationToken cancellationToken)
    {
        var userRoles = await GetUserRoles(new UserRoleCriteria { ResourceId = resourceId, UserId = userId },
            cancellationToken);

        // these are the user's own permissions, asked by their request, which confirms the membership
        if (userRoles.Any(x => x.ConfirmedTime == null))
            await ConfirmUserRoles(resourceId, userId, cancellationToken);

        var roles = _roles.Where(x => userRoles.Any(y => y.Role.RoleId == x.RoleId))
            .DistinctBy(x => x.RoleId);

        var permissions = roles.SelectMany(x => x.Permissions).ToList();

        var parentResourceId = await _roleResourceProvider.GetParentResourceId(resourceId,
            cancellationToken) ?? RootResourceId;
        if (!IsRootResource(resourceId))
            permissions.AddRange(await GetUserPermissions(parentResourceId, userId, cancellationToken));

        return permissions.Distinct().ToArray();
    }

    public Task<IReadOnlyList<string>> GetRolePermissions(string resourceId, string roleId)
    {
        var permissions = _roles.Single(x => x.RoleId == roleId).Permissions;
        return Task.FromResult(permissions);
    }

    private bool IsRootResource(string resourceId)
    {
        return resourceId == RootResourceId;
    }
}