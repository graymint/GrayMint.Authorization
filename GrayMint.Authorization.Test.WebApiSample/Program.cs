using GrayMint.Authorization.Authentications.BotAuthentication;
using GrayMint.Authorization.Authentications.CognitoAuthentication;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.TeamControllers;
using GrayMint.Authorization.Test.WebApiSample.Persistence;
using GrayMint.Authorization.Test.WebApiSample.Security;
using GrayMint.Authorization.UserManagement.SimpleUserProviders;
using GrayMint.Common.AspNetCore;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.Test.WebApiSample;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var authConfiguration = builder.Configuration.GetSection("Auth");

        builder.AddGrayMintCommonServices(new GrayMintCommonOptions { AppName = "Web App Sample" }, new RegisterServicesOptions());
        builder.Services
            .AddAuthentication()
            .AddBotAuthentication(authConfiguration.Get<BotAuthenticationOptions>(), builder.Environment.IsProduction())
            .AddCognitoAuthentication(authConfiguration.Get<CognitoAuthenticationOptions>());

        var authenticationSchemes = authConfiguration.GetValue<string>("CognitoClientId") == "ignore"
            ? new[] { BotAuthenticationDefaults.AuthenticationScheme }
            : new[] { BotAuthenticationDefaults.AuthenticationScheme, CognitoAuthenticationDefaults.AuthenticationScheme };
        builder.Services.AddGrayMintRoleAuthorization(new RoleAuthorizationOptions { AuthenticationSchemes = authenticationSchemes } );
        builder.Services.AddGrayMintSimpleRoleProvider(new SimpleRoleProviderOptions { Roles = SimpleRole.GetAll(typeof(Roles)) }, options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintSimpleUserProvider(authConfiguration.Get<SimpleUserProviderOptions>(), options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
        builder.Services.AddGrayMintTeamController(builder.Configuration.GetSection("RoleController").Get<TeamControllerOptions>());
        builder.Services.AddDbContext<WebApiSampleDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

        // Add services to the container.
        var webApp = builder.Build();
        webApp.UseGrayMintCommonServices(new UseServicesOptions());
        await webApp.Services.UseGrayMintDatabaseCommand<WebApiSampleDbContext>(args);
        await webApp.Services.UseGrayMintSimpleUserProvider();
        await webApp.Services.UseGrayMintSimpleRoleProvider();

        await GrayMintApp.RunAsync(webApp, args);

    }

    public static void Google(object builder)
    {
        /*
        builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://accounts.google.com";
                options.Audience = "x.apps.googleusercontent.com";
            })
            .AddGoogle(options =>
            {
                options.ClientId = "xxx.apps.googleusercontent.com";
                options.ClientSecret = "xx";
            });
        */
        throw new NotImplementedException();
    }
}