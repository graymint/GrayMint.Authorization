using GrayMint.Authorization.Test.ItemService.Dtos;
using GrayMint.Authorization.Test.ItemService.Models;

namespace GrayMint.Authorization.Test.ItemService.DtoConverters;

public static class ItemConverter
{
    public static Item ToDto(this ItemModel model)
    {
        return new Item
        {
            ItemId = model.ItemId,
            ItemName = model.ItemName
        };
    }
}