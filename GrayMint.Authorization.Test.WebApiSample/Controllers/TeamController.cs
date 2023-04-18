using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Authorization.Test.WebApiSample.Models;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
public class TeamController : TeamControllerBase<App, int>
{
    private readonly WebApiSampleDbContext _dbContext;

    public TeamController(
        TeamService roleService,
        WebApiSampleDbContext dbContext) :
        base(roleService)
    {
        _dbContext = dbContext;
    }

    protected override string ToResourceId(int appId)
    {
        return appId == 0 ? GetRootResourceId() : appId.ToString();
    }

    protected override async Task<IEnumerable<App>> GetResources(IEnumerable<string> resourceIds)
    {
        var appIds = resourceIds.Except(new[] { GetRootResourceId() }).Select(int.Parse);
        var ret = await _dbContext.Apps
            .Where(x => appIds.Contains(x.AppId))
            .ToArrayAsync();
        return ret;
    }
}