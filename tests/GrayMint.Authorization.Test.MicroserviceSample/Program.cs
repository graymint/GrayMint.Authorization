using GrayMint.Authorization.MicroserviceAuthorization;
using GrayMint.Authorization.Test.ItemServices;
using GrayMint.Authorization.Test.ItemServices.Persistence;
using GrayMint.Authorization.Test.MicroserviceSample.Services;
using GrayMint.Common.AspNetCore;
using GrayMint.Common.OpenApi;
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
                .AddGrayMintOpenApi();

            // authentication & its controller
            builder.AddGrayMintCommonAuthorizationForMicroservice<AuthorizationProvider>();

            // Database (tests set IgnoreDb and register their own SQLite contexts)
            if (builder.Configuration["IgnoreDb"] != "1")
                services.AddDbContext<AppDbContext>(options =>
                    options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

            services.AddItemServices();

            var webApp = builder.Build();
            webApp.UseGrayMintCommonServices(new UseServicesOptions());
            webApp.UseGrayMintOpenApi(new UseOpenApiOptions { RedirectRootToUi = true });
            // Database first: EnsureCreated creates the database itself on a fresh machine, and the
            // authorization providers below only create their own tables (they cannot create the db).
            await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args, CancellationToken.None);
            await webApp.UseGrayMintCommonAuthorizationForMicroservice();

            await GrayMintApp.RunAsync(webApp, args);
        }
    }
}