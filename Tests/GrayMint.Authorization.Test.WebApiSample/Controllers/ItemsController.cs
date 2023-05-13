using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.Test.WebApiSample.Models;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
[Route("/api/v{version:apiVersion}/apps/{appId:int}/items")]
public class ItemsController : ControllerBase
{
    private readonly WebApiSampleDbContext _dbContext;

    public ItemsController(WebApiSampleDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpPost]
    [Authorize(RoleAuthorization.Policy, Roles = 
        $"{nameof(Roles.SystemAdmin)},{nameof(Roles.AppOwner)},{nameof(Roles.AppAdmin)},{nameof(Roles.AppWriter)}")]
    public async Task<Item> Create(int appId, string itemName)
    {
        var ret = await _dbContext.Items.AddAsync(new Item { AppId = appId, ItemName = itemName });
        await _dbContext.SaveChangesAsync();
        return ret.Entity;
    }

    [HttpPost("by-permission")]
    [AuthorizePermission(Permissions.ItemWrite)]
    public async Task<Item> CreateByPermission(int appId, string itemName)
    {
        var ret = await _dbContext.Items.AddAsync(new Item { AppId = appId, ItemName = itemName });
        await _dbContext.SaveChangesAsync();
        return ret.Entity;
    }

    [HttpGet("itemId")]
    [Authorize(RoleAuthorization.Policy, Roles = 
        $"{nameof(Roles.SystemAdmin)},{nameof(Roles.AppOwner)},{nameof(Roles.AppAdmin)},{nameof(Roles.AppWriter)},{nameof(Roles.AppReader)}")]
    public async Task<Item> Get(int appId, int itemId)
    {
        var ret = await _dbContext.Items.SingleAsync(x => x.AppId == appId && x.ItemId == itemId);
        return ret;
    }

    [HttpGet("itemId/by-permission")]
    [AuthorizePermission(Permissions.ItemRead)]
    public async Task<Item> GetByPermission(int appId, int itemId)
    {
        var ret = await _dbContext.Items.SingleAsync(x => x.AppId == appId && x.ItemId == itemId);
        return ret;
    }

    [HttpDelete]
    [AuthorizePermission(Permissions.ItemWrite)]
    public async Task DeleteByPermission(int appId, string itemName)
    {
        var item = await _dbContext.Items.SingleAsync(x => x.AppId == appId && x.ItemName == itemName);
        _dbContext.Items.Remove(item);
        await _dbContext.SaveChangesAsync();
    }

}