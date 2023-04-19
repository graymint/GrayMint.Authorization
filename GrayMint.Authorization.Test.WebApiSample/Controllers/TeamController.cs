using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Authorization.Test.WebApiSample.Models;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
public class TeamController : TeamControllerBase<int>
{
    private readonly WebApiSampleDbContext _dbContext;

    public TeamController(
        TeamService roleService,
        WebApiSampleDbContext dbContext) :
        base(roleService)
    {
        _dbContext = dbContext;
    }

    protected override int RootResourceId => 0;

    [Authorize]
    [HttpGet("users/current/apps")]
    public async Task<IEnumerable<App>> ListCurrentUserApps()
    {
        var resourceIds = await ListCurrentUserResources();

        var appIds = resourceIds
            .Where(x => x != RootResourceId.ToString())
            .Select(int.Parse);

        var ret = await _dbContext.Apps
            .Where(x => appIds.Contains(x.AppId))
            .ToArrayAsync();
        return ret;
    }
}