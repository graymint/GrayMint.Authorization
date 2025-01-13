using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Services;
using GrayMint.Authorization.Test.MicroserviceSample.Security;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.MicroserviceSample.Controllers;

[ApiController]
[Route("/api/apps")]
public class AppsController(
    AppService appService)
    : ControllerBase
{
    [HttpPost]
    [AuthorizePermission(Permissions.AppCreate)]
    public Task<App> CreateApp(AppCreateRequest? createRequest = null)
    {
        return appService.Create(createRequest);
    }

    [HttpGet]
    [AuthorizePermission(Permissions.AppRead)]
    public Task<App[]> List()
    {
        return appService.List();

    }
}