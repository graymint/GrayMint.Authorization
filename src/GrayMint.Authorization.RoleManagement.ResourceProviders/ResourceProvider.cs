using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Models;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public class ResourceProvider(
    ResourceDbContext resourceDbContext,
    UserAuthorizationCache userAuthorizationCache,
    IRoleProvider roleProvider)
    : IResourceProvider
{
    public string RootResourceId => AuthorizationConstants.RootResourceId;

    public async Task<Resource> Add(Resource resource, CancellationToken cancellationToken)
    {
        resourceDbContext.ChangeTracker.Clear();
        resource.ParentResourceId ??= RootResourceId;
        var effectedResourceIds = await ValidateResourceParent(resource, cancellationToken);

        var entry = await resourceDbContext.Resources.AddAsync(resource.ToModel(), cancellationToken);
        await resourceDbContext.SaveChangesAsync(cancellationToken);

        await ClearResourceCache(effectedResourceIds, cancellationToken);
        return entry.Entity.ToDto();
    }

    public async Task<Resource> Update(Resource resource, CancellationToken cancellationToken)
    {
        resourceDbContext.ChangeTracker.Clear();
        resource.ParentResourceId ??= RootResourceId;
        if (resource.ResourceId == RootResourceId)
            throw new InvalidOperationException("Root resource cannot be updated.");

        var curResource = await Get(resource.ResourceId, cancellationToken);
        var effectedResourceIdsSrc = await ValidateResourceParent(curResource, cancellationToken);
        var effectedResourceIdsDes = await ValidateResourceParent(resource, cancellationToken);

        var entry = resourceDbContext.Resources.Update(resource.ToModel());
        await resourceDbContext.SaveChangesAsync(cancellationToken);

        // invalidate users in parent sources and destination
        await ClearResourceCache(effectedResourceIdsDes, cancellationToken);
        await ClearResourceCache(effectedResourceIdsSrc, cancellationToken);
        return entry.Entity.ToDto();
    }


    public async Task<Resource> Get(string resourceId, CancellationToken cancellationToken)
    {
        var resource = await resourceDbContext.Resources
            .AsNoTracking()
            .SingleAsync(x => x.ResourceId == resourceId, cancellationToken);

        return resource.ToDto() ?? throw new KeyNotFoundException();
    }

    public async Task Remove(string resourceId, CancellationToken cancellationToken)
    {
        resourceDbContext.ChangeTracker.Clear();
        if (resourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        var resource = await resourceDbContext.Resources
            .SingleAsync(x => x.ResourceId == resourceId, cancellationToken);

        var effectedResourceIds = await ValidateResourceParent(resource.ToDto(), cancellationToken);

        var deletedItems = new List<ResourceModel>();
        await DeleteRecursive(resource, deletedItems, cancellationToken);
        await resourceDbContext.SaveChangesAsync(cancellationToken);

        await roleProvider.RemoveUserRoles(new UserRoleCriteria { ResourceId = resourceId }, cancellationToken);
        await ClearResourceCache(effectedResourceIds, cancellationToken);
    }

    private async Task DeleteRecursive(ResourceModel resource, ICollection<ResourceModel> resources,
        CancellationToken cancellationToken)
    {
        var children = await resourceDbContext.Resources
            .AsNoTracking()
            .Where(x => x.ParentResourceId == resource.ResourceId)
            .ToArrayAsync(cancellationToken);

        foreach (var child in children)
            await DeleteRecursive(child, resources, cancellationToken);

        resources.Add(resource);
        resourceDbContext.Resources.Remove(resource);
    }

    // return this resource and parent resource ids
    private async Task<IReadOnlyList<string>> ValidateResourceParent(Resource resource,
        CancellationToken cancellationToken)
    {
        var parentIds = new List<string>();
        if (resource is { ResourceId: AuthorizationConstants.RootResourceId, ParentResourceId: not null })
            throw new InvalidOperationException("Parent of the root resource must be null.");

        while (resource.ParentResourceId != null) {
            parentIds.Add(resource.ResourceId);
            if (parentIds.Contains(resource.ParentResourceId))
                throw new InvalidOperationException("Loop detected in resource hierarchy.");

            resource = await Get(resource.ParentResourceId, cancellationToken);
        }

        return parentIds;
    }

    private async Task ClearResourceCache(IEnumerable<string> resourceIds, CancellationToken cancellationToken)
    {
        foreach (var resourceId in resourceIds) {
            var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resourceId },
                cancellationToken);
            foreach (var userRole in userRoles)
                userAuthorizationCache.ClearUserItems(userRole.UserId);
        }
    }
}