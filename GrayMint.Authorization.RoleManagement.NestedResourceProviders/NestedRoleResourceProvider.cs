using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.RoleManagement.NestedResourceProviders;

internal class NestedRoleResourceProvider : IRoleResourceProvider
{
    private readonly ResourceDbContext _resourceDbContext;

    public NestedRoleResourceProvider(ResourceDbContext resourceDbContext)
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