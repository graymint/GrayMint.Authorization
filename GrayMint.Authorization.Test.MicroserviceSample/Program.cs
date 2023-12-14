
using GrayMint.Authorization.MicroserviceAuthorization;
using GrayMint.Authorization.Test.MicroserviceSample.Persistence;
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
            var appOptions = builder.Configuration.GetSection("App").Get<AppOptions>() ?? throw new Exception("Could not load AppOptions.");
            services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

            // common services
            services
                .AddGrayMintCommonServices(new RegisterServicesOptions())
                .AddGrayMintSwagger("Test", true);

            // authentication & its controller
            builder.AddGrayMintCommonAuthorizationForMicroservice<AuthorizationProvider>();


            // Database
            services.AddDbContext<AppDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

            // Add services to the container.
            var webApp = builder.Build();
            webApp.UseGrayMintCommonServices(new UseServicesOptions());
            webApp.UseGrayMintSwagger(true);
            await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args);

            await GrayMintApp.RunAsync(webApp, args);
        }
    }
}
