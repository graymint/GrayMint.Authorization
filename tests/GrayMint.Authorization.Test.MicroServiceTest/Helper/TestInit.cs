using System.Net.Http.Headers;
using GrayMint.Authorization.Test.ItemServices.Persistence;
using GrayMint.Authorization.Test.MicroserviceSample;
using GrayMint.Common.Test.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ApiKey = GrayMint.Common.Test.Api.ApiKey;

namespace GrayMint.Authorization.Test.MicroServiceTest.Helper;

public class TestInit : IDisposable
{
    // Tests default to a private in-memory SQLite database: isolated per TestInit and fully
    // self-contained, so no SQL Server is required (CI runners have none). Developer-only
    // override: create a gitignored testsettings.local.json next to this test project with
    // { "UseSqlite": false } to run against the real database from appsettings.json.
    private static readonly bool UseSqlite = TestSettings.UseSqlite;
    private readonly SqliteConnection? _sqliteConnection;
    private readonly CancellationToken _cancellationToken;
    private App? _app;
    private ApiKey? _systemAdminApiKey;
    public WebApplicationFactory<Program> WebApp { get; }
    public HttpClient HttpClient { get; set; }
    public IServiceScope Scope { get; }
    public App App => _app ?? throw new InvalidOperationException("The app is made when the test starts.");
    public int AppId => App.AppId;
    public string AppResourceId => App.AppId.ToString();
    public string RootResourceId => "*";
    public AppsClient AppsClient => new(HttpClient);
    public ItemsClient ItemsClient => new(HttpClient);
    public AuthorizationClient AuthorizationClient => new(HttpClient);

    public ApiKey SystemAdminApiKey =>
        _systemAdminApiKey ?? throw new InvalidOperationException("The system admin is made when the test starts.");

    private TestInit(Dictionary<string, string?> appSettings, string environment, CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;

        // IgnoreDb tells the sample's Program to skip its SqlServer registration; the context is
        // then re-registered below on the shared SQLite connection.
        if (UseSqlite) {
            appSettings["IgnoreDb"] = "1";
            _sqliteConnection = new SqliteConnection("DataSource=:memory:");
            _sqliteConnection.Open();
        }

        // Application
        WebApp = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder => {
                foreach (var appSetting in appSettings)
                    builder.UseSetting(appSetting.Key, appSetting.Value);

                builder.UseEnvironment(environment);
                builder.ConfigureServices(services => {
                    if (_sqliteConnection != null)
                        services.AddDbContext<AppDbContext>(options => options.UseSqlite(_sqliteConnection));
                });
            });

        // Client
        HttpClient = WebApp.CreateClient(new WebApplicationFactoryClientOptions {
            AllowAutoRedirect = false
        });

        // Create System user
        Scope = WebApp.Services.CreateScope();
    }

    private async Task Init()
    {
        _systemAdminApiKey = await AuthorizationClient.CreateSystemApiKeyAsync(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", _cancellationToken);

        SetApiKey(_systemAdminApiKey);
        _app = await AppsClient.CreateAppAsync(new AppCreateRequest { AppName = Guid.NewGuid().ToString() },
            _cancellationToken);
    }

    public void SetApiKey(ApiKey apiKey)
    {
        HttpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue(apiKey.AccessToken.Scheme, apiKey.AccessToken.Value);
    }

    public static async Task<TestInit> Create(
        Dictionary<string, string?>? appSettings = null,
        string environment = "Development",
        CancellationToken cancellationToken = default)
    {
        appSettings ??= [];
        var testInit = new TestInit(appSettings, environment, cancellationToken);
        await testInit.Init();

        return testInit;
    }

    public void Dispose()
    {
        Scope.Dispose();
        HttpClient.Dispose();
        WebApp.Dispose();
        _sqliteConnection?.Dispose();
    }
}