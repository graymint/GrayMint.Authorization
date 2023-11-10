using System.Net.Http.Headers;
using System.Security.Claims;
using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.Test.WebApiSample;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Common.Test.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using ApiKey = GrayMint.Common.Test.Api.ApiKey;

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
    public INestedResourceProvider NestedResourceProvider => Scope.ServiceProvider.GetRequiredService<INestedResourceProvider>();
    public IUserProvider UserProvider => Scope.ServiceProvider.GetRequiredService<IUserProvider>();
    public GrayMintAuthenticationOptions AuthenticationOptions => WebApp.Services.GetRequiredService<IOptions<GrayMintAuthenticationOptions>>().Value;
    public AppsClient AppsClient => new(HttpClient);
    public ItemsClient ItemsClient => new(HttpClient);
    public TeamClient TeamClient => new(HttpClient);
    public AuthenticationClient AuthenticationClient => new(HttpClient);
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
        SystemAdminApiKey = await TeamClient.CreateSystemApiKeyAsync();
        HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(SystemAdminApiKey.AccessToken.Scheme, SystemAdminApiKey.AccessToken.Value);
        App = await AppsClient.CreateAppAsync(Guid.NewGuid().ToString());
    }

    public async Task<ApiKey> AddNewBot(SimpleRole simpleRole, bool setAsCurrent = true)
    {
        var oldAuthorization = HttpClient.DefaultRequestHeaders.Authorization;
        HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(SystemAdminApiKey.AccessToken.Scheme, SystemAdminApiKey.AccessToken.Value);

        var resourceId = simpleRole.IsRoot ? RootResourceId : AppResourceId;
        var apiKey = await TeamClient.AddNewBotAsync(resourceId, simpleRole.RoleId, new TeamAddBotParam { Name = Guid.NewGuid().ToString() });

        HttpClient.DefaultRequestHeaders.Authorization = setAsCurrent
            ? new AuthenticationHeaderValue(apiKey.AccessToken.Scheme, apiKey.AccessToken.Value) : oldAuthorization;

        return apiKey;
    }

    public async Task<UserRole> AddNewUser(SimpleRole simpleRole)
    {
        var resourceId = simpleRole.IsRoot ? RootResourceId : AppResourceId;
        var teamUserRole = await TeamClient.AddUserByEmailAsync(resourceId, simpleRole.RoleId, NewEmail());
        return teamUserRole;
    }

    public async Task<string> CreateUnregisteredUserIdToken(
        string? email = null, Claim[]? claims = null)
    {
        email ??= NewEmail();

        var claimsIdentity = new ClaimsIdentity();
        claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Email, email));
        claimsIdentity.AddClaim(new Claim(GrayMintClaimTypes.EmailVerified, "true"));
        if (claims != null) claimsIdentity.AddClaims(claims);

        var grayMintAuthentication = Scope.ServiceProvider.GetRequiredService<GrayMintAuthentication>();
        var token = await grayMintAuthentication.CreateIdToken(claimsIdentity);
        return token.Value;
    }

    public async Task<ApiKey> SignUpNewUser(string? email = null, Claim[]? claims = null, 
        bool setAsCurrent = true, RefreshTokenType refreshTokenType = RefreshTokenType.None)
    { 
        var idToken = await CreateUnregisteredUserIdToken(email, claims);
        var apiKey = await AuthenticationClient.SignUpAsync(
            new SignUpRequest { IdToken = idToken, RefreshTokenType = refreshTokenType });

        if (setAsCurrent) SetApiKey(apiKey);
        return apiKey;
    }

    public void SetApiKey(ApiKey apiKey)
    {
        HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(apiKey.AccessToken.Scheme, apiKey.AccessToken.Value);
    }

    public static async Task<TestInit> Create(Dictionary<string, string?>? appSettings = null,
        string environment = "Development", bool allowUserMultiRole = false, 
        bool useNestedResource = false)
    {
        appSettings ??= new Dictionary<string, string?>();
        appSettings["TeamController:AllowUserMultiRole"] = allowUserMultiRole.ToString();
        appSettings["App:UseNestedResource"] = useNestedResource.ToString();
        var testInit = new TestInit(appSettings, environment);
        await testInit.Init();

        // add app as the resource
        if (useNestedResource)
            await testInit.NestedResourceProvider.Add(new Resource { ResourceId = testInit.AppId.ToString() });

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