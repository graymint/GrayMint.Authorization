using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

internal class RoleResourceProvider : IRoleResourceProvider
{
    private readonly ResourceDbContext _resourceDbContext;

    public RoleResourceProvider(ResourceDbContext resourceDbContext)
    {
        _resourceDbContext = resourceDbContext;
    }

    public async Task<string?> GetParentResourceId(string resourceId)
    {
        if (resourceId == AuthorizationConstants.RootResourceId)
            return null;

        var resource =  await _resourceDbContext.Resources
            .SingleAsync(x => x.ResourceId == resourceId);

        return resource.ParentResourceId;
    }
}