using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.Test.WebApiSample.Models;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
[Route("/api/v{version:apiVersion}/apps")]
public class AppsController : ControllerBase
{
    private readonly WebApiSampleDbContext _dbContext;
    private readonly ILogger<App> _logger;

    public AppsController(
        WebApiSampleDbContext dbContext, 
        ILogger<App> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    [HttpPost]
    [AuthorizePermission(Permissions.SystemWrite)]
    public async Task<App> CreateApp(string appName)
    {
        _logger.LogInformation("Creating app. AppName: {appName}", appName);

        var ret = await _dbContext.Apps.AddAsync(new App { AppName = appName });
        await _dbContext.SaveChangesAsync();
        return ret.Entity;
    }

    [HttpGet]
    [AuthorizePermission(Permissions.SystemRead)]
    public async Task<App[]> List()
    {
        var ret = await _dbContext.Apps.ToArrayAsync();
        await _dbContext.SaveChangesAsync();
        return ret;
    }
}