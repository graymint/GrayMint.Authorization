using GrayMint.Authorization.Test.ItemServices.DtoConverters;
using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Models;
using GrayMint.Authorization.Test.ItemServices.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.ItemServices.Services;

public class AppService(AppDbContext appDbContext)
{
    public async Task<App> Create(AppCreateRequest? createRequest)
    {
        createRequest ??= new AppCreateRequest { AppName = Guid.NewGuid().ToString() };

        // Create App
        var app = await appDbContext.Apps.AddAsync(new AppModel {
            AppName = createRequest.AppName
        });

        await appDbContext.SaveChangesAsync();

        return app.Entity.ToDto();
    }

    public async Task<AppModel> Get(int appId)
    {
        var app = await appDbContext.Apps
            .SingleAsync(x => x.AppId == appId);

        return app;
    }

    public async Task<App[]> Get(IEnumerable<int> appIds)
    {
        var apps = await appDbContext.Apps
            .Where(x => appIds.Contains(x.AppId))
            .ToArrayAsync();

        return apps.Select(x => x.ToDto()).ToArray();
    }

    public async Task<App[]> List()
    {
        var apps = await appDbContext.Apps
            .ToArrayAsync();

        return apps.Select(x => x.ToDto()).ToArray();
    }

    public async Task UpdateAuthorizationCode(int appId, string authorizationCode)
    {
        // get max token id
        var app = await appDbContext.Apps.SingleAsync(x => x.AppId == appId);
        app.AuthorizationCode = authorizationCode;
        await appDbContext.SaveChangesAsync();
    }

    public async Task<string?> GetAuthorizationCode(int appId)
    {
        var app = await appDbContext.Apps.SingleAsync(x => x.AppId == appId);
        return app.AuthorizationCode;
    }
}