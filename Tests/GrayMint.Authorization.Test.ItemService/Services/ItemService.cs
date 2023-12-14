using GrayMint.Authorization.Test.ItemService.DtoConverters;
using GrayMint.Authorization.Test.ItemService.Dtos;
using GrayMint.Authorization.Test.ItemService.Models;
using GrayMint.Authorization.Test.ItemService.Persistence;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.ItemService.Services;

public class ItemService(AppDbContext appDbContext)
{

    public async Task<Item> Create(int appId, ItemCreateRequest createRequest)
    {
        // Create App
        var itemEntry = await appDbContext.Items.AddAsync(new ItemModel
        {
            AppId = appId,
            ItemName = createRequest.ItemName
        });

        await appDbContext.SaveChangesAsync();
        return itemEntry.Entity.ToDto();
    }

    public async Task<Item> Get(int appId, int itemId)
    {
        var item = await appDbContext.Items
            .SingleAsync(x => x.AppId == appId && x.ItemId == itemId);

        return item.ToDto();
    }

    public async Task<Item> Update(int appId, int itemId, ItemUpdateRequest updateRequest)
    {
        var item = await appDbContext.Items
            .SingleAsync(x => x.AppId == appId && x.ItemId == itemId);

        if (updateRequest.ItemName != null) item.ItemName = updateRequest.ItemName;
        return item.ToDto();
    }

    public async Task<Item[]> List(int appId)
    {
        var items = await appDbContext.Items
            .Where(x => x.AppId == appId)
            .ToArrayAsync();

        return items.Select(x => x.ToDto()).ToArray();
    }

    public async Task Delete(int appId, int itemId)
    {
        var item = await appDbContext.Items
            .SingleAsync(x => x.AppId == appId && x.ItemId == itemId);

        appDbContext.Remove(item);
        await appDbContext.SaveChangesAsync();
    }
}