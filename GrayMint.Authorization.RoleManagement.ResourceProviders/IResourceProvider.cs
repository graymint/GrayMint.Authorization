using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public interface IResourceProvider
{
    string RootResourceId { get; }
    Task<Resource> Add(Resource resource);
    Task<Resource> Update(Resource resource);
    Task<Resource> Get(string resourceId);
    Task Remove(string resourceId);
}