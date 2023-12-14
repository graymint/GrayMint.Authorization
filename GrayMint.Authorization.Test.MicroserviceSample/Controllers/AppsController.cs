using GrayMint.Authorization.PermissionAuthorizations;
using GrayMint.Authorization.Test.MicroserviceSample.Models;
using GrayMint.Authorization.Test.MicroserviceSample.Persistence;
using GrayMint.Authorization.Test.MicroserviceSample.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.MicroserviceSample.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Route("/api/v{version:apiVersion}/apps")]
public class AppsController : ControllerBase
{
    private readonly AppDbContext _appDbContext;
    private readonly ILogger<AppModel> _logger;

    public AppsController(
        AppDbContext appDbContext,
        ILogger<AppModel> logger)
    {
        _appDbContext = appDbContext;
        _logger = logger;
    }

    [HttpPost]
    [AuthorizePermission(Permissions.AppCreate)]
    public async Task<AppModel> CreateApp(string appName)
    {
        _logger.LogInformation("Creating app. AppName: {appName}", appName);

        var ret = await _appDbContext.Apps.AddAsync(new AppModel { AppName = appName });
        await _appDbContext.SaveChangesAsync();
        return ret.Entity;
    }

    [HttpGet]
    [AuthorizePermission(Permissions.AppCreate)]
    public async Task<AppModel[]> List()
    {
        var ret = await _appDbContext.Apps.ToArrayAsync();
        await _appDbContext.SaveChangesAsync();
        return ret;
    }
}