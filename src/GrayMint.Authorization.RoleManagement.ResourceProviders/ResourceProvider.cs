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
    public string RootResourceId { get; } = AuthorizationConstants.RootResourceId;

    public async Task<Resource> Add(Resource resource)
    {
        resourceDbContext.ChangeTracker.Clear();
        resource.ParentResourceId ??= RootResourceId; // set default parent
        var effectedResourceIds = await ValidateResourceParent(resource);

        var entry = await resourceDbContext.Resources.AddAsync(resource.ToModel());
        await resourceDbContext.SaveChangesAsync();

        await ClearResourceCache(effectedResourceIds);
        return entry.Entity.ToDto();
    }

    public async Task<Resource> Update(Resource resource)
    {
        resourceDbContext.ChangeTracker.Clear();
        resource.ParentResourceId ??= RootResourceId; // set default parent
        if (resource.ResourceId == RootResourceId)
            throw new InvalidOperationException("Root resource cannot be updated.");

        var curResource = await Get(resource.ResourceId);
        var effectedResourceIdsSrc = await ValidateResourceParent(curResource);
        var effectedResourceIdsDes = await ValidateResourceParent(resource);

        // update database
        var entry = resourceDbContext.Resources.Update(resource.ToModel());
        await resourceDbContext.SaveChangesAsync();

        // invalidate users in parent sources and destination
        await ClearResourceCache(effectedResourceIdsDes);
        await ClearResourceCache(effectedResourceIdsSrc);
        return entry.Entity.ToDto();
    }


    public async Task<Resource> Get(string resourceId)
    {
        var resource = await resourceDbContext.Resources
            .AsNoTracking()
            .SingleAsync(x => x.ResourceId == resourceId);

        return resource.ToDto() ?? throw new KeyNotFoundException();
    }

    public async Task Remove(string resourceId)
    {
        resourceDbContext.ChangeTracker.Clear();
        if (resourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        // get model
        var resource = await resourceDbContext.Resources
            .SingleAsync(x => x.ResourceId == resourceId);

        // get effected resource ids
        var effectedResourceIds = await ValidateResourceParent(resource.ToDto());

        // delete from database
        var deletedItems = new List<ResourceModel>();
        await DeleteRecursive(resource, deletedItems);
        await resourceDbContext.SaveChangesAsync();

        // clean user roles
        await roleProvider.RemoveUserRoles(new UserRoleCriteria { ResourceId = resourceId });
        await ClearResourceCache(effectedResourceIds);
    }

    private async Task DeleteRecursive(ResourceModel resource, ICollection<ResourceModel> resources)
    {
        var children = await resourceDbContext.Resources
            .AsNoTracking()
            .Where(x => x.ParentResourceId == resource.ResourceId)
            .ToArrayAsync();

        foreach (var child in children)
            await DeleteRecursive(child, resources);

        resources.Add(resource);
        resourceDbContext.Resources.Remove(resource);
    }

    // return this resource and parent resource ids
    private async Task<string[]> ValidateResourceParent(Resource resource)
    {
        var parentIds = new List<string>();
        if (resource is { ResourceId: AuthorizationConstants.RootResourceId, ParentResourceId: not null })
            throw new InvalidOperationException("Parent of the root resource must be null.");

        while (resource.ParentResourceId != null) {
            parentIds.Add(resource.ResourceId);
            if (parentIds.Contains(resource.ParentResourceId))
                throw new InvalidOperationException("Loop detected in resource hierarchy.");

            resource = await Get(resource.ParentResourceId);
        }

        return parentIds.ToArray();
    }

    private async Task ClearResourceCache(IEnumerable<string> resourceIds)
    {
        foreach (var resourceId in resourceIds) {
            var userRoles = await roleProvider.GetUserRoles(new UserRoleCriteria { ResourceId = resourceId });
            foreach (var userRole in userRoles)
                userAuthorizationCache.ClearUserItems(userRole.UserId);
        }
    }
}