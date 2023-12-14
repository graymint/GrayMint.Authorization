using GrayMint.Authorization.Test.ItemService.Dtos;
using GrayMint.Authorization.Test.ItemService.Models;

namespace GrayMint.Authorization.Test.ItemService.DtoConverters;

public static class AppConverter
{
    public static App ToDto(this AppModel model)
    {
        return new App
        {
            AppId = model.AppId,
            AppName = model.AppName
        };
    }
}