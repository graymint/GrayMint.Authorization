using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleProvider : IRoleAuthorizationProvider
{
    Task<UserRole> AddUser(string resourceId, string roleId, string userId);
    Task RemoveUser(string resourceId, string roleId, string userId);
    Task<Role[]> GetRoles(string resourceId);
    Task<Role> Get(string resourceId, string roleId);
    Task<Role?> FindByName(string resourceId, string roleName);
    Task<string[]> GetRolePermissions(string resourceId, string roleId);
    Task<ListResult<UserRole>> GetUserRoles(string? resourceId = null, string? roleId = null, string? userId = null, 
        int recordIndex = 0, int? recordCount = null);
}