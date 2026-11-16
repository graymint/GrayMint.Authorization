using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using GrayMint.Authorization.OpenIdAuthentications;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.UserProviders;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace GrayMint.Authorization.Test.OpenIdAuthenticationTest.Helper;

// A small service that takes the tokens of the test's providers, over a database of its own: one address
// that only a user may call, and one where an application signs its person in.
public sealed class TestHost : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly SqliteConnection _connection;

    public HttpClient Client { get; }
    public IServiceProvider Services => _app.Services;

    private TestHost(WebApplication app, SqliteConnection connection)
    {
        _app = app;
        _connection = connection;
        Client = app.GetTestClient();
    }

    public static Task<TestHost> Create(TestProvider provider)
    {
        return Create(new TestHostOptions { Providers = [provider] });
    }

    public static async Task<TestHost> Create(TestHostOptions options)
    {
        // one connection that stays open: the database lives in memory for as long as it does
        var connection = new SqliteConnection("DataSource=:memory:");
        await connection.OpenAsync();

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddGrayMintUserProvider(null);
        builder.Services.AddGrayMintUserProviderDb(x => x.UseSqlite(connection));
        builder.Services.AddGrayMintOpenIdAuthenticationDb(x => x.UseSqlite(connection));
        builder.Services
            .AddAuthentication(OpenIdAuthenticationDefaults.AuthenticationScheme)
            .AddGrayMintOpenIdAuthentication(new OpenIdAuthenticationOptions {
                Providers = options.Providers.Select(x => x.CreateOptions()).ToArray(),
                AllowSelfRegister = options.AllowSelfRegister
            });

        // before the schemes make the client they read a provider's keys with
        var providerHandler = new TestProviderHandler(options.Providers);
        builder.Services.ConfigureAll<JwtBearerOptions>(x => x.BackchannelHttpHandler = providerHandler);
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (ClaimsPrincipal user) => Results.Text(user.FindFirstValue(ClaimTypes.NameIdentifier)))
            .RequireAuthorization();
        app.MapPost("/sign-in",
            (HttpRequest request, OpenIdSignInService signInService) => SignIn(request, signInService));

        await app.Services.UseGrayMintUserProvider();
        await app.Services.UseGrayMintOpenIdAuthentication();
        await app.StartAsync();
        return new TestHost(app, connection);
    }

    // a user made by hand, as a service does before the person ever signs in
    public async Task<User> CreateUser(string email)
    {
        await using var scope = Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<IUserProvider>()
            .Create(new UserCreateRequest { Email = email });
    }

    // what an application does with the ID token it got for its person
    public async Task<TestSignInResponse> SignIn(string idToken, CancellationToken cancellationToken)
    {
        using var response = await Client.PostAsync("/sign-in", new StringContent(idToken), cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TestSignInResponse>(cancellationToken) ??
               throw new InvalidOperationException("The sign-in gave no answer.");
    }

    // the address that only a user may call, with the access token given
    public async Task<HttpResponseMessage> GetMe(string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return await Client.SendAsync(request, cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
        await _connection.DisposeAsync();
    }

    private static async Task<IResult> SignIn(HttpRequest request, OpenIdSignInService signInService)
    {
        using var reader = new StreamReader(request.Body);
        var idToken = await reader.ReadToEndAsync(request.HttpContext.RequestAborted);
        var result = await signInService.SignIn(idToken, request.HttpContext.RequestAborted);
        return Results.Json(new TestSignInResponse { Status = result.Status.ToString(), UserId = result.User?.UserId });
    }
}
