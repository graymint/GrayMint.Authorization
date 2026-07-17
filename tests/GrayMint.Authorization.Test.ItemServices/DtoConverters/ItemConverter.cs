using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Models;

namespace GrayMint.Authorization.Test.ItemServices.DtoConverters;

public static class ItemConverter
{
    public static Item ToDto(this ItemModel model)
    {
        return new Item {
            ItemId = model.ItemId,
            ItemName = model.ItemName
        };
    }
}