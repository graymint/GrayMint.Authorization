using System;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleProvider : IRoleAuthorizationProvider
{
    Task<IUserRole> AddUser(string resourceId, Guid roleId, Guid userId);
    Task RemoveUser(string resourceId, Guid roleId, Guid userId);
    Task<IRole[]> GetRoles(string resourceId);
    Task<IRole> Get(string resourceId, Guid roleId);
    Task<IRole?> FindByName(string resourceId, string roleName);
    Task<string[]> GetRolePermissions(string resourceId, Guid roleId);
    Task<ListResult<IUserRole>> GetUserRoles(string? resourceId = null, Guid? roleId = null, Guid? userId = null, 
        int recordIndex = 0, int? recordCount = null);
}