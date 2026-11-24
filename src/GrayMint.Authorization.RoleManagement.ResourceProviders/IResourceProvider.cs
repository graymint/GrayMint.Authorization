using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public interface IResourceProvider
{
    string RootResourceId { get; }
    Task<Resource> Add(Resource resource, CancellationToken cancellationToken);
    Task<Resource> Update(Resource resource, CancellationToken cancellationToken);
    Task<Resource> Get(string resourceId, CancellationToken cancellationToken);
    Task Remove(string resourceId, CancellationToken cancellationToken);
}