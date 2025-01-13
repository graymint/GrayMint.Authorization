using GrayMint.Authorization.RoleManagement.ResourceProviders;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;
using GrayMint.Authorization.Test.ItemServices;
using GrayMint.Authorization.Test.ItemServices.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Common.AspNetCore;
using GrayMint.Common.Swagger;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample;

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
            .AddGrayMintSwagger("Test", false);

        // authentication & its controller
        builder.AddGrayMintCommonAuthorizationForApp(
            GmRole.GetAll(typeof(Roles)), 
            options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // nested resource controller. MUST be after role provider
        if (appOptions.UseResourceProvider)
            services.AddGrayMintResourceProvider(new ResourceProviderOptions(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // Database
        services.AddDbContext<AppDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        services.AddItemServices();

        // Add services to the container.
        var webApp = builder.Build();
        webApp.UseGrayMintCommonServices(new UseServicesOptions());
        webApp.UseGrayMintSwagger(true);
        webApp.UseStaticFiles(new StaticFileOptions());
        await webApp.UseGrayMinCommonAuthorizationForApp();
        await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args);
        if (appOptions.UseResourceProvider)
            await webApp.Services.UseGrayMintResourceProvider();

        await GrayMintApp.RunAsync(webApp, args);
    }
}