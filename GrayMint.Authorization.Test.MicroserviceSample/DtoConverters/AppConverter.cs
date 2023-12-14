using GrayMint.Authorization.Test.MicroserviceSample.Dtos;
using GrayMint.Authorization.Test.MicroserviceSample.Models;

namespace GrayMint.Authorization.Test.MicroserviceSample.DtoConverters;

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