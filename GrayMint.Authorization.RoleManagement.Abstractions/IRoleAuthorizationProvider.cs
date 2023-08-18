using System;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleAuthorizationProvider
{
    Task<string[]> GetUserPermissions(string resourceId, Guid userId);
    Task<ListResult<IUserRole>> GetUserRoles(Guid userId);
    Task<ListResult<IUserRole>> GetUserRoles(string resourceId, Guid userId);
}