using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleAuthorizationProvider
{
    Task<string[]> GetUserPermissions(string resourceId, string userId);
    Task<ListResult<UserRole>> GetUserRoles(string userId);
    Task<ListResult<UserRole>> GetUserRoles(string resourceId, string userId);
}