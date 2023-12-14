using GrayMint.Authorization.Test.ItemServices.Dtos;
using GrayMint.Authorization.Test.ItemServices.Models;

namespace GrayMint.Authorization.Test.ItemServices.DtoConverters;

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