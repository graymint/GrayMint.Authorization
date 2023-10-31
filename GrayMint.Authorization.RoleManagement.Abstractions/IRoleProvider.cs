using System;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleProvider : IRoleAuthorizationProvider
{
    Task<UserRole> AddUser(string resourceId, Guid roleId, Guid userId);
    Task RemoveUser(string resourceId, Guid roleId, Guid userId);
    Task<Role[]> GetRoles(string resourceId);
    Task<Role> Get(string resourceId, Guid roleId);
    Task<Role?> FindByName(string resourceId, string roleName);
    Task<string[]> GetRolePermissions(string resourceId, Guid roleId);
    Task<ListResult<UserRole>> GetUserRoles(string? resourceId = null, Guid? roleId = null, Guid? userId = null, 
        int recordIndex = 0, int? recordCount = null);
}