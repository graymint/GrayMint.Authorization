using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public class SimpleResourceProvider
{
    private readonly SimpleRoleDbContext _simpleRoleDbContext;
    private readonly IMemoryCache _memoryCache;
    public string RootResourceId { get; }

    public SimpleResourceProvider(
        SimpleRoleDbContext simpleRoleDbContext, IMemoryCache memoryCache)
    {
        _simpleRoleDbContext = simpleRoleDbContext;
        _memoryCache = memoryCache;
        RootResourceId = AuthorizationConstants.RootResourceId;
    }


    public async Task<Resource> Create(Resource resource)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        await ValidateResourceParent(resource);

        var entry = await _simpleRoleDbContext.Resources.AddAsync(resource.ToModel());
        await _simpleRoleDbContext.SaveChangesAsync();
        return entry.Entity.ToDto();
    }

    public async Task<Resource> Get(string resourceId)
    {
        var resource = await _simpleRoleDbContext.Resources
            .AsNoTracking()
            .SingleAsync(x => x.ResourceId == resourceId);

        return resource.ToDto() ?? throw new KeyNotFoundException();
    }

    public async Task<Resource> Update(Resource resource)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        if (resource.ResourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        await ValidateResourceParent(resource);

        var entry = _simpleRoleDbContext.Resources.Update(resource.ToModel());

        await _simpleRoleDbContext.SaveChangesAsync();
        return entry.Entity.ToDto();
    }
    public async Task Remove(string resourceId)
    {
        _simpleRoleDbContext.ChangeTracker.Clear();
        if (resourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        // delete from database
        var resource = await _simpleRoleDbContext.Resources
            .Include(x => x.UserRoles)
            .SingleAsync(x => x.ResourceId == resourceId);

        var deletedItems = new List<ResourceModel>();
        await DeleteRecursive(resource, deletedItems);
        await _simpleRoleDbContext.SaveChangesAsync();

        // remove all resource from cache
        foreach (var item in deletedItems)
        {
            foreach (var userRole in item.UserRoles!)
                AuthorizationCache.ResetUser(_memoryCache, userRole.UserId.ToString().ToLower());
        }
    }

    private async Task DeleteRecursive(ResourceModel resource, ICollection<ResourceModel> resources)
    {
        var children = await _simpleRoleDbContext.Resources
            .Include(x => x.UserRoles)
            .Where(x => x.ParentResourceId == resource.ResourceId)
            .ToArrayAsync();

        foreach (var child in children)
            await DeleteRecursive(child, resources);

        resources.Add(resource);
        _simpleRoleDbContext.Resources.Remove(resource);
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
}