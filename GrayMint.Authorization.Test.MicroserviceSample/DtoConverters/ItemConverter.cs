
using GrayMint.Authorization.Test.MicroserviceSample.Dtos;
using GrayMint.Authorization.Test.MicroserviceSample.Models;

namespace GrayMint.Authorization.Test.MicroserviceSample.DtoConverters;

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