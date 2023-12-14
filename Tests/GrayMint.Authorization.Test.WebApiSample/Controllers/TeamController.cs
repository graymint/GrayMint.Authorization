using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;
using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
public class TeamController(
    TeamService teamService,
    AppService appService) 
    : TeamControllerBase(teamService)
{
    [Authorize]
    [HttpGet("users/current/apps")]
    public async Task<IEnumerable<App>> ListCurrentUserApps()
    {
        var resourceIds = await ListCurrentUserResources();

        var appIds = resourceIds
            .Where(x => x != GetRootResourceId())
            .Select(int.Parse);

        return await appService.Get(appIds);
    }
}