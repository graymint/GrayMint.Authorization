using System.Net.Http.Headers;
using System.Security.Claims;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Authentications.BotAuthentication;
using GrayMint.Authorization.Authentications.CognitoAuthentication;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.Test.WebApiSample;
using GrayMint.Common.Test.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace GrayMint.Authorization.Test.Helper;

public class TestInit : IDisposable
{
    public WebApplicationFactory<Program> WebApp { get; }
    public HttpClient HttpClient { get; set; }
    public IServiceScope Scope { get; }
    public App App { get; private set; } = default!;
    public int AppId => App.AppId;
    public string AppResourceId => App.AppId.ToString();
    public string RootResourceId => "*";
    public CognitoAuthenticationOptions CognitoAuthenticationOptions => WebApp.Services.GetRequiredService<IOptions<CognitoAuthenticationOptions>>().Value;
    public AppsClient AppsClient => new(HttpClient);
    public ItemsClient ItemsClient => new(HttpClient);
    public TeamClient TeamClient => new(HttpClient);
    public UserApiKey SystemAdminApiKey { get; private set; } = default!;


    private TestInit(Dictionary<string, string?> appSettings, string environment)
    {
        // Application
        WebApp = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                foreach (var appSetting in appSettings)
                    builder.UseSetting(appSetting.Key, appSetting.Value);

                builder.UseEnvironment(environment);
                builder.ConfigureServices(services =>
                {
                    services.AddScoped<IAuthorizationProvider, TestBotAuthenticationProvider>();
                });
            });

        // Client
        HttpClient = WebApp.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Create System user
        Scope = WebApp.Services.CreateScope();
    }

    private async Task Init()
    {
        SystemAdminApiKey = await TeamClient.CreateSystemApiKeyAsync();
        HttpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(SystemAdminApiKey.Authorization);
        App = await AppsClient.CreateAppAsync(Guid.NewGuid().ToString());
    }

    public async Task<UserApiKey> AddNewBot(SimpleRole simpleRole, bool setAsCurrent = true)
    {
        var oldAuthorization = HttpClient.DefaultRequestHeaders.Authorization;
        HttpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(SystemAdminApiKey.Authorization);

        var resourceId = simpleRole.IsRoot ? RootResourceId : AppResourceId;
        var apiKey = await TeamClient.AddNewBotAsync(resourceId, simpleRole.RoleId, new TeamAddBotParam { Name = Guid.NewGuid().ToString() });

        HttpClient.DefaultRequestHeaders.Authorization = setAsCurrent
            ? AuthenticationHeaderValue.Parse(apiKey.Authorization) : oldAuthorization;

        return apiKey;
    }

    public async Task<TeamUserRole> AddNewUser(SimpleRole simpleRole)
    {
        var resourceId = simpleRole.IsRoot ? RootResourceId : AppResourceId;
        var teamUserRole = await TeamClient.AddUserByEmailAsync(resourceId, simpleRole.RoleId, NewEmail());
        return teamUserRole;
    }

    public async Task<AuthenticationHeaderValue> CreateUnregisteredUser(
        string? email = null, Claim[]? claims = null, bool setAsCurrent = true)
    {
        email ??= NewEmail();

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim("test_authenticated", "1"));
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, email));
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        if (claims != null) claimsIdentity.AddClaims(claims);

        var authenticationTokenBuilder = Scope.ServiceProvider.GetRequiredService<BotAuthenticationTokenBuilder>();
        var authorization = await authenticationTokenBuilder.CreateAuthenticationHeader(new CreateTokenParams
        {
            ClaimsIdentity = claimsIdentity
        });

        if (setAsCurrent)
            HttpClient.DefaultRequestHeaders.Authorization = authorization;

        return authorization;
    }

    public void SetApiKey(UserApiKey apiKey)
    {
        HttpClient.DefaultRequestHeaders.Authorization = AuthenticationHeaderValue.Parse(apiKey.Authorization);
    }

    public static async Task<TestInit> Create(Dictionary<string, string?>? appSettings = null,
        string environment = "Development", bool useCognito = false, bool allowUserMultiRole = false)
    {
        appSettings ??= new Dictionary<string, string?>();
        if (!useCognito) appSettings["Auth:CognitoClientId"] = "ignore";
        appSettings["TeamController:AllowUserMultiRole"] = allowUserMultiRole.ToString();
        var testInit = new TestInit(appSettings, environment);
        await testInit.Init();
        return testInit;
    }

    public static string NewEmail()
    {
        return $"{Guid.NewGuid()}@local";
    }

    public void Dispose()
    {
        Scope.Dispose();
        HttpClient.Dispose();
        WebApp.Dispose();
    }
}