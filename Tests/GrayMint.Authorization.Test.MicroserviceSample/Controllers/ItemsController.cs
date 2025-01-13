using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Services;
using GrayMint.Authorization.Test.MicroserviceSample.Security;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.MicroserviceSample.Controllers;

[ApiController]
[Route("/api/apps/{appId:int}/items")]
public class ItemsController(ItemService itemService) : ControllerBase
{
    [HttpPost]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task<Item> Create(int appId, ItemCreateRequest? createRequest = null)
    {
        return itemService.Create(appId, createRequest);
    }

    [HttpGet]
    [AuthorizeAppIdPermission(Permissions.AppRead)]
    public Task<Item[]> List(int appId)
    {
        return itemService.List(appId);
    }


    [HttpGet("{itemId:int}")]
    [AuthorizeAppIdPermission(Permissions.AppRead)]
    public Task<Item> Get(int appId, int itemId)
    {
        return itemService.Get(appId, itemId);
    }

    [HttpPatch("{itemId:int}")]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task<Item> Update(int appId, int itemId, ItemUpdateRequest updateRequest)
    {
        return itemService.Update(appId, itemId, updateRequest);
    }

    [HttpDelete("{itemId:int}")]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task Delete(int appId, int itemId)
    {
        return itemService.Delete(appId, itemId);
    }
}