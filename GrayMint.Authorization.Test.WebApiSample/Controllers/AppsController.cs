using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.WebApiSample.Models;
using GrayMint.Authorization.WebApiSample.Persistence;
using GrayMint.Authorization.WebApiSample.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.WebApiSample.Controllers;

[ApiController]
[Route("/api/v{version:apiVersion}/apps")]
public class AppsController : ControllerBase
{
    private readonly WebApiSampleDbContext _dbContext;

    public AppsController(WebApiSampleDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    [HttpPost]
    [AuthorizePermission(Permissions.SystemWrite)]
    public async Task<App> CreateApp(string appName)
    {
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