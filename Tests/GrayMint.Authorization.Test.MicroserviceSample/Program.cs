using GrayMint.Authorization.MicroserviceAuthorization;
using GrayMint.Authorization.Test.ItemServices;
using GrayMint.Authorization.Test.ItemServices.Persistence;
using GrayMint.Authorization.Test.MicroserviceSample.Services;
using GrayMint.Common.AspNetCore;
using GrayMint.Common.Swagger;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.MicroserviceSample
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var services = builder.Services;

            // options
            services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

            // common services
            services
                .AddGrayMintCommonServices(new RegisterServicesOptions())
                .AddGrayMintSwagger("Test", false);

            // authentication & its controller
            builder.AddGrayMintCommonAuthorizationForMicroservice<AuthorizationProvider>();

            // Database
            services.AddDbContext<AppDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
            services.AddItemServices();

            // Add services to the container.
            var webApp = builder.Build();
            webApp.UseGrayMintCommonServices(new UseServicesOptions());
            webApp.UseGrayMintSwagger(true);
            await webApp.UseGrayMinCommonAuthorizationForMicroservice();
            await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args);

            await GrayMintApp.RunAsync(webApp, args);
        }
    }
}
