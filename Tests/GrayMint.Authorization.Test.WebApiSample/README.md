# GrayMint.Authorization.Test.WebApiSample

A sample ASP.NET Core Web API project demonstrating the GrayMint Authorization framework with role-based access control, team management, and resource providers.

## Features

- 🔐 **JWT Authentication** with support for multiple OAuth providers (Google, AWS Cognito, Firebase)
- 👥 **Role-Based Access Control (RBAC)** with customizable roles and permissions
- 🏢 **Team Management** with role assignments and hierarchical access
- 📦 **Resource Providers** for nested resource authorization
- 🔑 **API Key Authentication** (configurable)
- 🔄 **Refresh Token Support**
- 📚 **Interactive API Documentation** with Scalar UI

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- SQL Server or SQL Server Express
- Visual Studio 2022 or Visual Studio Code

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/graymint/GrayMint.Authorization.git
cd GrayMint.Authorization/Tests/GrayMint.Authorization.Test.WebApiSample
```

### 2. Configure the Application

Update the `appsettings.json` file with your configuration:

#### Database Connection

```json
"ConnectionStrings": {
  "AppDatabase": "Server=localhost;Database=GrayMintAuthTest;Trusted_Connection=True;TrustServerCertificate=True;"
}
```

#### Authentication Settings

```json
"Auth": {
  "Issuer": "YourAppName",
  "Audience": "YourAppName",
  "Secret": "your-secure-secret-key-at-least-32-characters-long",
  "AllowRefreshToken": true,
  "SignInRedirectUrl": "https://localhost:5001/sign-in"
}
```

> ⚠️ **Security Note**: Change the `Secret` to a strong, unique value in production. Use environment variables or Azure Key Vault for sensitive configuration.

#### OAuth Provider Configuration

Configure OpenID providers (optional):

```json
"Auth": {
  "OpenIdProviders": [
    {
      "Name": "Google",
      "Issuer": "https://accounts.google.com",
      "Audience": "your-google-client-id.apps.googleusercontent.com"
    }
  ]
}
```

### 3. Initialize the Database

Run the following command to create and migrate the database:

```bash
dotnet run -- database update
```

### 4. Run the Application

```bash
dotnet run
```

The application will start at:
- HTTPS: `https://localhost:5001`
- HTTP: `http://localhost:5000`

## API Documentation

This project uses **Scalar UI** for interactive API documentation, providing a modern and user-friendly interface to explore and test the API.

### Accessing the Documentation

Once the application is running, navigate to:

```
https://localhost:5001/scalar/v1
```

### Scalar UI Features

- 🎨 **Modern, Dark Theme** - Beautiful interface with Moon theme
- 🔍 **Interactive API Explorer** - Test endpoints directly from the browser
- 📝 **Request/Response Examples** - Auto-generated examples for all endpoints
- 🔐 **Authentication Support** - Easy token management for secured endpoints
- 💻 **Code Generation** - Generate C# HttpClient code snippets

### Alternative: Swagger UI

Swagger UI is also available at:

```
https://localhost:5001/swagger
```

## Configuration Options

### App Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `UseResourceProvider` | Enable nested resource authorization | `true` |

### Authentication Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `Issuer` | JWT token issuer | `WebAppSample` |
| `Audience` | JWT token audience | `WebAppSample` |
| `Secret` | Secret key for token signing | Required |
| `CacheTimeout` | Authorization cache duration | `00:05:00` |
| `AllowUserSelfRegister` | Allow user self-registration | `false` |
| `AllowUserApiKey` | Enable API key authentication | `false` |
| `AllowRefreshToken` | Enable refresh token support | `true` |
| `SignInRedirectUrl` | Redirect URL after sign-in | Required |

### Team Controller Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `AllowBotAppOwner` | Allow bot accounts as owners | `false` |
| `AllowUserMultiRole` | Allow users to have multiple roles | `false` |

## Project Structure

```
GrayMint.Authorization.Test.WebApiSample/
??? Controllers/
?   ??? CustomersController.cs      # Sample controller with authorization
??? Security/
?   ??? Roles.cs             # Role definitions
?   ??? AuthorizeCustomerIdPermissionAttribute.cs
??? wwwroot/       # Static files
??? Program.cs   # Application startup
??? appsettings.json      # Configuration
??? README.md     # This file
```

## Key Endpoints

### Authentication

- `POST /api/auth/sign-in` - Sign in with credentials
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/register` - Register new user (if enabled)

### User Management

- `GET /api/users` - List users
- `GET /api/users/{userId}` - Get user details
- `PUT /api/users/{userId}` - Update user
- `DELETE /api/users/{userId}` - Delete user

### Team Management

- `GET /api/teams` - List teams
- `POST /api/teams` - Create team
- `GET /api/teams/{teamId}` - Get team details
- `POST /api/teams/{teamId}/members` - Add team member
- `DELETE /api/teams/{teamId}/members/{userId}` - Remove team member

### Resource Management

- `GET /api/resources` - List resources
- `POST /api/resources` - Create resource
- `GET /api/resources/{resourceId}` - Get resource details

## Authorization Examples

### Role-Based Authorization

```csharp
[Authorize(Roles = "Admin")]
[HttpGet]
public IActionResult GetAdminData()
{
    return Ok("Admin data");
}
```

### Permission-Based Authorization

```csharp
[AuthorizePermission("customers:read")]
[HttpGet]
public IActionResult GetCustomers()
{
    return Ok(customers);
}
```

### Custom Authorization

```csharp
[AuthorizeCustomerIdPermission("customers:update")]
[HttpPut("{customerId}")]
public IActionResult UpdateCustomer(string customerId, CustomerDto dto)
{
    return Ok();
}
```

## Database Commands

The application includes CLI commands for database management:

```bash
# Update database to latest migration
dotnet run -- database update

# Drop database
dotnet run -- database drop

# Check migration status
dotnet run -- database status
```

## Testing

Run the integration tests:

```bash
cd ../GrayMint.Authorization.Test.WebApiSampleTest
dotnet test
```

## Technologies Used

- **ASP.NET Core 9** - Web framework
- **Entity Framework Core** - ORM
- **SQL Server** - Database
- **JWT Bearer Authentication** - Token-based auth
- **OpenAPI/Scalar** - API documentation
- **GrayMint.Common** - Common utilities

## Related Projects

- [GrayMint.Authorization](../../GrayMint.Authorization) - Core authorization library
- [GrayMint.Authorization.Authentications](../../GrayMint.Authorization.Authentications) - Authentication services
- [GrayMint.Authorization.RoleManagement](../../GrayMint.Authorization.RoleManagement.RoleProviders) - Role management
- [GrayMint.Authorization.UserManagement](../../GrayMint.Authorization.UserManagement.UserProviders) - User management

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](../../LICENSE) file for details.

## Support

For questions or issues:
- 📧 Open an issue on [GitHub](https://github.com/graymint/GrayMint.Authorization/issues)
- 📖 Check the [documentation](https://github.com/graymint/GrayMint.Authorization)
- 💬 Join the discussion in GitHub Discussions

## Acknowledgments

- Built with [ASP.NET Core](https://docs.microsoft.com/aspnet/core)
- API documentation powered by [Scalar](https://github.com/scalar/scalar)
- Developed by [GrayMint](https://github.com/graymint)
