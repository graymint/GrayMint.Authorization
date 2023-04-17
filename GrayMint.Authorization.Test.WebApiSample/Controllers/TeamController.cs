using GrayMint.Authorization.RoleManagement.RoleControllers.Controllers;
using GrayMint.Authorization.RoleManagement.RoleControllers.Services;
using GrayMint.Authorization.WebApiSample.Models;
using GrayMint.Authorization.WebApiSample.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.WebApiSample.Controllers;

[ApiController]
public class TeamController : TeamControllerBase<App, int>
{
    private readonly WebApiSampleDbContext _dbContext;

    public TeamController(
        RoleService roleService,
        WebApiSampleDbContext dbContext) :
        base(roleService)
    {
        _dbContext = dbContext;
    }

    protected override string ToResourceId(int appId)
    {
        return appId == 0 ? RoleService.GetRootResourceId() : appId.ToString();
    }

    protected override async Task<IEnumerable<App>> GetResources(IEnumerable<string> resourceIds)
    {
        var appIds = resourceIds.Except(new[] { RoleService.GetRootResourceId() }).Select(int.Parse);
        var ret = await _dbContext.Apps
            .Where(x => appIds.Contains(x.AppId))
            .ToArrayAsync();
        return ret;
    }
}