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
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public class SimpleResourceProvider
{
    private readonly SimpleRoleProviderOptions _simpleRoleProviderOptions;
    private readonly SimpleRoleDbContext _simpleRoleDbContext;
    private readonly IMemoryCache _memoryCache;

    public SimpleResourceProvider(
        SimpleRoleDbContext simpleRoleDbContext,
        IMemoryCache memoryCache, 
        IOptions<SimpleRoleProviderOptions> simpleRoleProviderOptions)
    {
        _simpleRoleDbContext = simpleRoleDbContext;
        _memoryCache = memoryCache;
        _simpleRoleProviderOptions = simpleRoleProviderOptions.Value;
        RootResourceId = AuthorizationConstants.RootResourceId;
    }

    public string RootResourceId { get; } 

    private static string GetCacheKeyForResource(string resourceId)
    {
        return $"graymint:auth:resource-provider:resources:{resourceId}";
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
        var resource = await _memoryCache.GetOrCreateAsync(GetCacheKeyForResource(resourceId), async entry =>
        {
            entry.SlidingExpiration = _simpleRoleProviderOptions.CacheTimeout;
            return await _simpleRoleDbContext.Resources
                .AsNoTracking()
                .SingleAsync(x => x.ResourceId == resourceId);
        }) ;

        return resource?.ToDto() ?? throw new KeyNotFoundException();
    }

    public async Task<Resource> Update(Resource resource)
    {
        if (resource.ResourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        _simpleRoleDbContext.ChangeTracker.Clear();
        await ValidateResourceParent(resource);

        var entry = _simpleRoleDbContext.Resources.Update(resource.ToModel());
        
        await _simpleRoleDbContext.SaveChangesAsync();
        _memoryCache.Remove(GetCacheKeyForResource(resource.ResourceId));
        return entry.Entity.ToDto();
    }
    public async Task Delete(string resourceId)
    {
        if (resourceId == AuthorizationConstants.RootResourceId)
            throw new InvalidOperationException("Root resource cannot be deleted.");

        // delete from database
        _simpleRoleDbContext.ChangeTracker.Clear();
        var resource = await _simpleRoleDbContext.Resources.SingleAsync(x => x.ResourceId == resourceId);
        var resourceIds = new List<string>();
        await DeleteRecursive(resource, resourceIds);
        await _simpleRoleDbContext.SaveChangesAsync();

        // remove from cache
        foreach (var id in resourceIds)
            _memoryCache.Remove(GetCacheKeyForResource(id));
    }

    private async Task DeleteRecursive(ResourceModel resource, ICollection<string> resourceIds)
    {
        var children =  await _simpleRoleDbContext.Resources
            .Where(x => x.ParentResourceId == resource.ResourceId)
            .ToArrayAsync();

        foreach (var child in children)
            await DeleteRecursive(child, resourceIds);

        resourceIds.Add(resource.ResourceId);
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