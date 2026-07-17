namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRoleResourceProvider
{
    Task<string?> GetParentResourceId(string resourceId);
}