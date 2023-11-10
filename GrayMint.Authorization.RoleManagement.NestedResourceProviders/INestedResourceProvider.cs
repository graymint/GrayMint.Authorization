using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.NestedResourceProviders;

public interface INestedResourceProvider
{
    string RootResourceId { get; }
    Task<Resource> Add(Resource resource);
    Task<Resource> Update(Resource resource);
    Task<Resource> Get(string resourceId);
    Task Remove(string resourceId);
}