using GrayMint.Authorization.Test.ItemServices.Services;
using Microsoft.Extensions.DependencyInjection;

namespace GrayMint.Authorization.Test.ItemServices;

public static class ItemServicesExtension
{
    public static IServiceCollection AddItemServices(this IServiceCollection services)
    {
        services.AddScoped<AppService>();
        services.AddScoped<ItemService>();
        return services;
    }
}