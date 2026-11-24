namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleAuthorizationProvider
{
    // the permissions of the request's own user: asking for them on a resource is that user's use of
    // it, which confirms their membership there, so never ask it for another user
    Task<IReadOnlyList<string>> GetUserPermissions(string resourceId, string userId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<UserRole>> GetUserRoles(UserRoleCriteria userRoleCriteria, CancellationToken cancellationToken);
}