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
        var authConfiguration = builder.Configuration.GetSection("Auth");
        var appOptions = builder.Configuration.GetSection("App").Get<AppOptions>() ?? throw new Exception("Could not load AppOptions.");
        builder.Services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

        builder.Services.AddGrayMintCommonServices(new GrayMintCommonOptions(), new RegisterServicesOptions());
        builder.Services
            .AddAuthentication()
            .AddGrayMintAuthentication(authConfiguration.Get<GrayMintAuthenticationOptions>(), builder.Environment.IsProduction());

        builder.Services.AddGrayMintRoleAuthorization();
        builder.Services.AddGrayMintUserProvider(authConfiguration.Get<UserProviderOptions>(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintRoleProvider(new RoleProviderOptions { Roles = SimpleRole.GetAll(typeof(Roles)) }, options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintAuthenticationController();
        builder.Services.AddGrayMintTeamController(builder.Configuration.GetSection("TeamController").Get<TeamControllerOptions>());
        builder.Services.AddGrayMintSwagger("Test", true);
        builder.Services.AddDbContext<WebApiSampleDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        if (appOptions.UseResourceProvider)
            builder.Services.AddGrayMintResourceProvider(new ResourceProviderOptions(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // Add authorization
        builder.Services.AddAuthorization(options =>
        {
            // create default policy
            var policyBuilder = new AuthorizationPolicyBuilder();
            policyBuilder.RequireAuthenticatedUser();
            policyBuilder.AddAuthenticationSchemes(GrayMintAuthenticationDefaults.AuthenticationScheme);

            var defaultPolicy = policyBuilder.Build();
            options.AddPolicy("DefaultPolicy", defaultPolicy);
            options.DefaultPolicy = defaultPolicy;
        });

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