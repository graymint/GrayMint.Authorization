using GrayMint.Authorization.RoleManagement.TeamControllers.Services;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.RoleManagement.TeamControllers;

public static class TeamControllerExtension
{
    public static void AddGrayMintTeamController(this IServiceCollection services,
        TeamControllerOptions? options = null)
    {
        options ??= new TeamControllerOptions();
        services.AddSingleton(Options.Create(options));
        services.AddScoped<TeamService>();
    }
}