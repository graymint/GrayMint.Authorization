using System.Threading.Tasks;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleAuthorizationProvider
{
    Task<string[]> GetUserPermissions(string resourceId, string userId);
    Task<UserRole[]> GetUserRoles(UserRoleCriteria userRoleCriteria);
}