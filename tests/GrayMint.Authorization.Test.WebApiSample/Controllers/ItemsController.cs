using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Services;
using GrayMint.Authorization.Test.WebApiSample.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Route("/api/apps/{appId}/items")]
public class ItemsController(ItemService itemService)
    : ControllerBase
{
    [HttpPost("by-role")]
    [Authorize(Policy = "DefaultPolicy",
        Roles =
            $"{nameof(Roles.SystemAdmin)},{nameof(Roles.AppOwner)},{nameof(Roles.AppAdmin)},{nameof(Roles.AppWriter)}")]
    public Task<Item> CreateByRole(int appId, ItemCreateRequest? createRequest = null)
    {
        return itemService.Create(appId, createRequest);
    }

    [HttpGet("itemId/by-role")]
    [Authorize("DefaultPolicy",
        Roles =
            $"{nameof(Roles.SystemAdmin)},{nameof(Roles.SystemReader)},{nameof(Roles.AppAdmin)},{nameof(Roles.AppWriter)},{nameof(Roles.AppReader)}")]
    public Task<Item> GetByRole(int appId, int itemId)
    {
        return itemService.Get(appId, itemId);
    }

    [HttpPost("by-permission")]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task<Item> CreateByPermission(int appId, ItemCreateRequest? createRequest = null)
    {
        return itemService.Create(appId, createRequest);
    }

    [HttpGet("itemId/by-permission")]
    [AuthorizeAppIdPermission(Permissions.AppRead)]
    public Task<Item> GetByPermission(int appId, int itemId)
    {
        return itemService.Get(appId, itemId);
    }

    [HttpDelete]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task DeleteByPermission(int appId, int itemId)
    {
        return itemService.Delete(appId, itemId);
    }
}