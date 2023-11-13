using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Controllers;
using GrayMint.Authorization.RoleManagement.ResourceProviders;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.RoleProviders;
using GrayMint.Authorization.RoleManagement.RoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.UserProviders;
using GrayMint.Common.AspNetCore;
using GrayMint.Common.Swagger;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;

        // options
        var authConfiguration = builder.Configuration.GetSection("Auth");
        var appOptions = builder.Configuration.GetSection("App").Get<AppOptions>() ?? throw new Exception("Could not load AppOptions.");
        services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

        // common services
        services.AddMemoryCache();
        services
            .AddGrayMintCommonServices(new RegisterServicesOptions() { AddMemoryCache = false })
            .AddGrayMintSwagger("Test", true);

        // authentication & its controller
        services
            .AddGrayMintAuthenticationController()
            .AddAuthentication()
            .AddGrayMintAuthentication(authConfiguration.Get<GrayMintAuthenticationOptions>()!, builder.Environment.IsProduction());

        // authorization & its controller
        services
            .AddGrayMintRoleAuthorization()
            .AddAuthorization(options =>
            {
                // create default policy
                var policyBuilder = new AuthorizationPolicyBuilder();
                policyBuilder.RequireAuthenticatedUser();
                policyBuilder.AddAuthenticationSchemes(GrayMintAuthenticationDefaults.AuthenticationScheme);

                var defaultPolicy = policyBuilder.Build();
                options.AddPolicy("DefaultPolicy", defaultPolicy);
                options.DefaultPolicy = defaultPolicy;
            });

        // users
        services
            .AddGrayMintUserProvider(authConfiguration.Get<UserProviderOptions>(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // roles & its controller
        services
            .AddGrayMintTeamController(builder.Configuration.GetSection("TeamController").Get<TeamControllerOptions>())
            .AddGrayMintRoleProvider(new RoleProviderOptions { Roles = GmRole.GetAll(typeof(Roles)) }, options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // nested resource controller. MUST be after role provider
        if (appOptions.UseResourceProvider)
            services.AddGrayMintResourceProvider(new ResourceProviderOptions(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // Database
        services.AddDbContext<WebApiSampleDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // Add services to the container.
        var webApp = builder.Build();
        webApp.UseGrayMintCommonServices(new UseServicesOptions());
        webApp.UseGrayMintSwagger();
        webApp.UseStaticFiles(new StaticFileOptions());
        await webApp.Services.UseGrayMintDatabaseCommand<WebApiSampleDbContext>(args);
        await webApp.Services.UseGrayMintUserProvider();
        await webApp.Services.UseGrayMintRoleProvider();
        if (appOptions.UseResourceProvider)
            await webApp.Services.UseGrayMintResourceProvider();

        await GrayMintApp.RunAsync(webApp, args);
    }
}