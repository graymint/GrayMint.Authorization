using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Models;
using GrayMint.Authorization.Test.ItemServices.Services;
using GrayMint.Authorization.Test.MicroserviceSample.Security;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.MicroserviceSample.Controllers;

[ApiController]
[Route("/api/v{version:apiVersion}/apps")]
public class AppsController(
    AppService appService,
    ILogger<AppModel> logger)
    : ControllerBase
{
    [HttpPost]
    [AuthorizePermission(Permissions.AppCreate)]
    public Task<App> CreateApp(AppCreateRequest createRequest)
    {
        logger.LogInformation("Creating app. AppName: {appName}", createRequest.AppName);
        return appService.Create(createRequest);
    }

    [HttpGet]
    [AuthorizePermission(Permissions.AppRead)]
    public Task<App[]> List()
    {
        return appService.List();

    }
}