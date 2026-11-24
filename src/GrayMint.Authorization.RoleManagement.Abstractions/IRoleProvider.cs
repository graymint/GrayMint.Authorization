using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleProvider : IRoleAuthorizationProvider
{
    Task<IReadOnlyList<Role>> GetRoles(string resourceId);
    Task<Role> GetRole(string resourceId, string roleId);
    Task<Role?> FindRoleByName(string resourceId, string roleName);
    Task<IReadOnlyList<string>> GetRolePermissions(string resourceId, string roleId);
    Task<UserRole> AddUserRole(string resourceId, string roleId, string userId, CancellationToken cancellationToken);
    Task RemoveUserRoles(UserRoleCriteria criteria, CancellationToken cancellationToken);
    Task<ListResult<UserRole>> GetUserRoles(UserRoleCriteria criteria, int recordIndex, int recordCount,
        CancellationToken cancellationToken);
}