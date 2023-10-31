using System;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleAuthorizationProvider
{
    Task<string[]> GetUserPermissions(string resourceId, Guid userId);
    Task<ListResult<UserRole>> GetUserRoles(Guid userId);
    Task<ListResult<UserRole>> GetUserRoles(string resourceId, Guid userId);
}