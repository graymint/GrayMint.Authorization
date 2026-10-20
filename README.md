# GrayMint.Authorization

**Modular B2B Authorization Framework for .NET Applications**

GrayMint.Authorization provides a flexible, multi-tenant-compatible B2B authorization framework for .NET apps. It enables role-based and resource-based access control, ideal for enterprise platforms, SaaS systems, and microservices.

---

## 🔧 Features

- Role-based and resource-based authorization
- Multi-tenant (B2B) ready
- Modular service registration and layering
- Microservice-compatible with extensible providers
- EF Core-based persistence support
- Built-in controllers and services for quick bootstrap

---

## 📦 Installation

Install the packages from [nuget.org](https://www.nuget.org/packages?q=GrayMint.Authorization):

```ps
dotnet add package GrayMint.Authorization
```

---

## 🚀 Getting Started

### 1. Configure App Settings
- `Issuer`: The issuer of the tokens.
- `Audience`: The audience of the tokens.
- `Audiences`: More audiences to accept but never to issue, such as the old one while a service moves its tokens to a new `Audience`.
- `Secret`: The secret key for token generation.
- `Secrets`: List of additional secret keys.
- `CacheTimeout`: The cache timeout duration.
- `AllowUserSelfRegister`: Boolean flag to allow or disallow user self-registration.
- `AllowUserApiKey`: Boolean flag to allow or disallow user API keys.
- `AllowRefreshToken`: Boolean flag to allow or disallow refresh tokens.
- `SignInRedirectUrl`: The URL to redirect to after sign-in.
- `OpenIdProviders`: List of OpenID providers with their respective configurations.
- `AllowSystemApiKey`: Allows the anonymous system api-key endpoints, which take the signing secret. Unset, they work outside production only.

Every access token carries an `authorization_code` claim, checked on each request so that the token can be revoked; a token without one is refused. A token meant to outlive any revocation, such as a customer token, carries `*`.

A person added to a resource by email shows to its team by email only until their first request to that resource, so adding an email shows the team nothing of that person's profile. Bots, which the team's own admins create, show in full.

Upgrading an existing SQL Server database: the role provider creates missing tables, not missing columns, so add `ConfirmedTime` before the new version starts. The members already on a team are confirmed once, with the column, so they keep showing in full:

```sql
IF COL_LENGTH('gmrole.UserRoles', 'ConfirmedTime') IS NULL
BEGIN
    ALTER TABLE [gmrole].[UserRoles] ADD [ConfirmedTime] datetime2(0) NULL
    EXEC('UPDATE [gmrole].[UserRoles] SET [ConfirmedTime] = SYSUTCDATETIME()')
END
```

Emails are looked up and stored lower-cased. On a database that compares text case-sensitively (PostgreSQL, SQLite), lower-case the emails already stored once, or an email stored in another case is not found and adding it again creates a second account.

### 2. Service Registration (from Sample Web API)
```csharp
var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

// Load options
var appOptions = builder.Configuration.GetSection("App").Get<AppOptions>();
services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

// Register shared services and Swagger
services
    .AddGrayMintCommonServices();

// Register Authorization and Roles
builder.AddGrayMintCommonAuthorizationForApp(
    GmRole.GetAll(typeof(Roles)),
    options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

// Optional: Register Resource Provider
if (appOptions.UseResourceProvider)
    services.AddGrayMintResourceProvider(
        new ResourceProviderOptions(),
        options => options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));

// Add EF Core & domain services
services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("AppDatabase")));
services.AddItemServices();
```

### 3. Middleware & Execution
```csharp
var webApp = builder.Build();
webApp.UseGrayMintCommonServices();
await webApp.UseGrayMinCommonAuthorizationForApp();
await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args);

if (appOptions.UseResourceProvider)
    await webApp.Services.UseGrayMintResourceProvider();

await GrayMintApp.RunAsync(webApp, args);
```

---

## 🧪 Permission Check Example

```csharp
    [HttpGet("itemId/by-role")]
    [Authorize("DefaultPolicy", Roles = ["SystemAdmin", "SystemReader"])
    public Task<Item> GetByRole(int appId, int itemId)
    {
        return itemService.Get(appId, itemId);
    }

    [HttpPost("by-permission")]
    [AuthorizeAppIdPermission(Permissions.AppWrite)]
    public Task<Item> CreateByPermission(int appId, ItemCreateRequest? createRequest = null)
    {
        return itemService.Create(appId, createRequest);
    }
```

---
## 🧩 Extending

Implement custom providers:
- `IRoleProvider`
- `IUserProvider`
- `IResourceProvider`

These interfaces allow full control over how roles, users, and resources are managed.

---

## 🏗 Repo layout & CI

- `src/` — the packable libraries; one shared version and package metadata via
  `src/Directory.Build.props`. `pub/PubVersion.json` is the version source of truth.
- `tests/` — test suites and sample hosts. Never packed.
- `.github/workflows/` — thin wrappers over the reusable CI in
  [GrayMint.Common](https://github.com/graymint/GrayMint.Common): every push to `main` builds,
  tests, bumps the version, and publishes to nuget.org; a daily job (02:30 UTC, right after
  GrayMint.Common's own update) upgrades all NuGet dependencies and republishes when tests pass.
  Nothing ships when tests fail.

Build locally:

```ps
dotnet build GrayMint.Authorization.slnx
dotnet test GrayMint.Authorization.slnx
```

## 📄 License

Licensed under the MIT License.


