using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Controllers;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.SimpleUserProviders;
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

        builder.AddGrayMintCommonServices(new GrayMintCommonOptions (), new RegisterServicesOptions());
        builder.Services
            .AddAuthentication()
            .AddGrayMintAuthentication(authConfiguration.Get<GrayMintAuthenticationOptions>(), builder.Environment.IsProduction());

        builder.Services.AddGrayMintRoleAuthorization();
        builder.Services.AddGrayMintSimpleRoleProvider(new SimpleRoleProviderOptions { Roles = SimpleRole.GetAll(typeof(Roles)) }, options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintSimpleUserProvider(authConfiguration.Get<SimpleUserProviderOptions>(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintAuthenticationController();
        builder.Services.AddGrayMintTeamController(builder.Configuration.GetSection("TeamController").Get<TeamControllerOptions>());
        builder.Services.AddGrayMintSwagger("Test", true);
        builder.Services.AddDbContext<WebApiSampleDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

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
        await webApp.Services.UseGrayMintDatabaseCommand<WebApiSampleDbContext>(args);
        await webApp.Services.UseGrayMintSimpleUserProvider();
        await webApp.Services.UseGrayMintSimpleRoleProvider();

        await GrayMintApp.RunAsync(webApp, args);

    }
}