using System.Net.Http.Headers;
using GrayMint.Authorization.Test.MicroserviceSample;
using GrayMint.Common.Test.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using ApiKey = GrayMint.Common.Test.Api.ApiKey;

namespace GrayMint.Authorization.Test.MicroServiceTest.Helper;

public class TestInit : IDisposable
{
    public WebApplicationFactory<Program> WebApp { get; }
    public HttpClient HttpClient { get; set; }
    public IServiceScope Scope { get; }
    public App App { get; private set; } = default!;
    public int AppId => App.AppId;
    public string AppResourceId => App.AppId.ToString();
    public string RootResourceId => "*";
    public AppsClient AppsClient => new(HttpClient);
    public ItemsClient ItemsClient => new(HttpClient);
    public AuthorizationClient AuthorizationClient => new(HttpClient);
    public ApiKey SystemAdminApiKey { get; private set; } = default!;


    private TestInit(Dictionary<string, string?> appSettings, string environment)
    {
        // Application
        WebApp = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                foreach (var appSetting in appSettings)
                    builder.UseSetting(appSetting.Key, appSetting.Value);

                builder.UseEnvironment(environment);
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
        SystemAdminApiKey = await AuthorizationClient.CreateSystemApiKeyAsync("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(SystemAdminApiKey.AccessToken.Scheme, SystemAdminApiKey.AccessToken.Value);
        App = await AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() });
    }

    public void SetApiKey(ApiKey apiKey)
    {
        HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(apiKey.AccessToken.Scheme, apiKey.AccessToken.Value);
    }

    public static async Task<TestInit> Create(
        Dictionary<string, string?>? appSettings = null,
        string environment = "Development")
    {
        appSettings ??= new Dictionary<string, string?>();
        var testInit = new TestInit(appSettings, environment);
        await testInit.Init();

        return testInit;
    }

    public void Dispose()
    {
        Scope.Dispose();
        HttpClient.Dispose();
        WebApp.Dispose();
    }
}