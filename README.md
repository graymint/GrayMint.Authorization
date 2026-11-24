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
- `AllowUserApiKey`: Boolean flag to allow or disallow user API keys. Without it, the service has no `api/authentication/current/reset-api-key` endpoint; bots' keys don't need it.
- `AllowRefreshToken`: Boolean flag to allow or disallow refresh tokens.
- `SignInRedirectUrl`: The URL to redirect to after sign-in.
- `OpenIdProviders`: List of OpenID providers with their respective configurations. Google's sign-in endpoints (`api/authentication/external/google/...`) exist only with a provider named `Google`.
- `AllowSystemApiKey`: Allows the anonymous system api-key endpoints, which take the signing secret. Unset, they work in Development only.

Every access token carries an `authorization_code` claim, checked on each request so that the token can be revoked; a token without one is refused. A token meant to outlive any revocation, such as a customer token, carries `*`.

A person added to a resource by email shows to its team by email only until their first request to that resource, so adding an email shows the team nothing of that person's profile. Bots, which the team's own admins create, show in full. Removing someone's last role deletes a bot, or an account an email add made that was never used, but never a person who has signed in.

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
await webApp.UseGrayMintCommonAuthorizationForApp(CancellationToken.None);
await webApp.Services.UseGrayMintDatabaseCommand<AppDbContext>(args, CancellationToken.None);

if (appOptions.UseResourceProvider)
    await webApp.Services.UseGrayMintResourceProvider(CancellationToken.None);

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

An `IAuthorizationProvider`'s answers for a token are cached by the token's claims, leaving out the ones every copy differs in (`jti`, `iat`, `exp`, `nbf`, and a refresh token's embedded access token), so they must not depend on those.

---

## 🔑 An OpenID Connect identity provider's tokens

`GrayMint.Authorization.OpenIdAuthentications` is a package of its own, for a service whose people sign in
at an OpenID Connect identity provider and that issues no tokens itself. It needs none of the
authentication packages above; the roles and permissions work with it as they are.

```cs
services
    .AddAuthentication(OpenIdAuthenticationDefaults.AuthenticationScheme)
    .AddGrayMintOpenIdAuthentication(new OpenIdAuthenticationOptions {
        Providers = [
            new OpenIdProviderOptions {
                Name = "main",                       // never changes: users are tied under it
                Issuer = "https://id.example.com/",  // as the provider's tokens carry it
                Audience = "files.example.com",      // this service, as its access tokens name it
                ClientIds = ["files"]                // the applications whose people sign in here
            }
        ]
    });
services.AddGrayMintOpenIdAuthenticationDb(options => options.UseNpgsql(connectionString));
```

- **An access token is taken only as the provider's own, for this service**: signed by a key the provider
  publishes, in the one way it signs, in its name, naming this service as its audience, not run out, and an
  access token by its own word (`typ` is `at+jwt`), which an ID token of the same provider is not. The
  provider's keys are read from its address, and again when a token names one that isn't known yet.
- **A name is read to its last letter.** An audience or an application whose name is this one's with a
  slash more is another one.
- **A caller is a user only by a binding**: the provider's own id of the account (`sub`), tied to a local
  user. An account that is tied to nobody is refused, whatever its token says; an address in a token ties
  nobody. The id may be as long as OpenID Connect allows, 255 characters.
- **`OpenIdSignInService.SignIn`** is what an application calls once, with the ID token it got for its
  person. The first time, it ties the account to the user of its address, on the provider's word that the
  address is the person's (`email_verified`), and only to a user that no account is tied to yet. Where
  `AllowSelfRegister` is on, someone who is no user yet becomes one then.
- **`OpenIdSignInService.SignUp`** is for a service whose people become users at a step of its own, such as
  a page where they accept its terms. It does what `SignIn` does, and someone who is no user yet becomes
  one, whatever `AllowSelfRegister` says. With the setting off, a sign-in alone makes nobody a user.
- **A user who was made by their address alone takes the name of the account that is tied to them**, once.
  A name the service gave them stays, and so does the one they took, whatever the account is called later.
- **A person who becomes a user by themselves is kept with their address in lower case**, however the
  provider spells it. A user made by hand is found by the address as the provider spells it, and then in
  lower case: write it in lower case, and a service that looks for people by a typed address finds each
  one once.
- **The ID token must be meant for one of the service's applications, and asked for by one of them.** A
  token says who asked for it (`azp`) when it is meant for several applications, and may say so anyway: one
  that another application asked for is refused, though it names one of the service's beside its own, and
  so is one for several that names nobody.
- A user is tied to one account, and an account to one user: the table's own keys hold that, also for two
  sign-ins that come at the same moment.
- **A locked user is tied to no account**: the one that tried while the user was locked would be the user's
  from the day the lock is taken off.
- **The tie of a user that was removed is dropped** when its account signs in next, and the account comes
  as for the first time. Left there, it would keep the person out for good, also once they are made a user
  again.

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


