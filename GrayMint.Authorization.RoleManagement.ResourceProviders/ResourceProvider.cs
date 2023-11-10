using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.ResourceProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Models;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders;

public class ResourceProvider : IResourceProvider
{
    private readonly ResourceDbContext _resourceDbContext;
    private readonly IRoleProvider _roleProvider;
    public string RootResourceId { get; }

    public ResourceProvider(
        ResourceDbContext resourceDbContext,
        IRoleProvider roleProvider)
    {
        _resourceDbContext = resourceDbContext;
        _roleProvider = roleProvider;
        RootResourceId = AuthorizationConstants.RootResourceId;
    }


    public async Task<Resource> Add(Resource resource)
    {
        _resourceDbContext.ChangeTracker.Clear();
        await ValidateResourceParent(resource);

        var entry = await _resourceDbContext.Resources.AddAsync(resource.ToModel());
        await _resourceDbContext.SaveChangesAsync();
        return entry.Entity.ToDto();
    }

    public async Task<Resource> Update(Resource resource)
    {
        _resourceDbContext.ChangeTracker.Clear();
        await ValidateResourceParent(resource);
        if (resource.ResourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be updated.");

        var entry = _resourceDbContext.Resources.Update(resource.ToModel());
        await _resourceDbContext.SaveChangesAsync();
        return entry.Entity.ToDto();
    }


    public async Task<Resource> Get(string resourceId)
    {
        var resource = await _resourceDbContext.Resources
            .AsNoTracking()
            .SingleAsync(x => x.ResourceId == resourceId);

        return resource.ToDto() ?? throw new KeyNotFoundException();
    }

    public async Task Remove(string resourceId)
    {
        _resourceDbContext.ChangeTracker.Clear();
        if (resourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        var resource = await _resourceDbContext.Resources
            .SingleAsync(x => x.ResourceId == resourceId);

        // delete from database
        var deletedItems = new List<ResourceModel>();
        await DeleteRecursive(resource, deletedItems);
        await _resourceDbContext.SaveChangesAsync();

        // clean user roles
        await _roleProvider.RemoveUserRoles(new UserRoleCriteria { ResourceId = resourceId });
    }

    private async Task DeleteRecursive(ResourceModel resource, ICollection<ResourceModel> resources)
    {
        var children = await _resourceDbContext.Resources
            .AsNoTracking()
            .Where(x => x.ParentResourceId == resource.ResourceId)
            .ToArrayAsync();

        foreach (var child in children)
            await DeleteRecursive(child, resources);

        resources.Add(resource);
        _resourceDbContext.Resources.Remove(resource);
    }

    private async Task ValidateResourceParent(Resource resource)
    {
        var parentIds = new List<string>();
        if (resource is { ResourceId: AuthorizationConstants.RootResourceId, ParentResourceId: not null })
            throw new InvalidOperationException("Parent of the root resource must be null.");

        while (resource.ParentResourceId != null)
        {
            parentIds.Add(resource.ResourceId);
            if (parentIds.Contains(resource.ParentResourceId))
                throw new InvalidOperationException("Loop detected in resource hierarchy.");

            resource = await Get(resource.ParentResourceId);
        }
    }

    public async Task<string?> GetParentResourceId(string resourceId)
    {
        var resource = await Get(resourceId);
        return resource.ParentResourceId;
    }
}