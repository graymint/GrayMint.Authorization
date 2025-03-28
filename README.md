# GrayMint.Authorization
B2B Authorization

# GrayMint.Authorization

**Modular B2B Authorization Framework for .NET Applications**

GrayMint.Authorization provides a flexible, multi-tenant-compatible (B2B) authorization framework for .NET apps. It enables role-based and resource-based access control, ideal for enterprise platforms, SaaS systems, and microservices.

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

Use the repository as a Git submodule or reference projects directly in your solution.

```ps
dotnet add package GrayMint.Authorization
```

---

## 🚀 Getting Started

### 1. Configure App Settings
```json
{
  "App": {
    "UseResourceProvider": true
  },
  "ConnectionStrings": {
    "AppDatabase": "Server=...;Database=...;Trusted_Connection=True;"
  }
}
```

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
var permissionChecker = serviceProvider.GetRequiredService<IPermissionChecker>();
var isAuthorized = await permissionChecker.CheckPermissionAsync(
    userId: 123,
    permission: "EditDocument",
    resourceId: 456
);
```

---
## 🧩 Extending

Implement custom providers:
- `IRoleProvider`
- `IUserProvider`
- `IResourceProvider`

These interfaces allow full control over how roles, users, and resources are managed.

---

## 📄 License

Licensed under the MIT License.


