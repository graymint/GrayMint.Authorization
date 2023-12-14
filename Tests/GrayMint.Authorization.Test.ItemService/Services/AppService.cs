using GrayMint.Authorization.Test.ItemService.DtoConverters;
using GrayMint.Authorization.Test.ItemService.Dtos;
using GrayMint.Authorization.Test.ItemService.Models;
using GrayMint.Authorization.Test.ItemService.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.ItemService.Services;

public class AppService(AppDbContext appDbContext)
{

    public async Task<App> Create(string appName)
    {
        // Create App
        var app = await appDbContext.Apps.AddAsync(new AppModel
        {
            AppName = appName
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