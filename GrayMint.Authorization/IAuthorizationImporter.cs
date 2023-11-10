using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.Authentications.Controllers.Controllers;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders;
using GrayMint.Authorization.RoleManagement.RoleProviders;
using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;
using GrayMint.Authorization.UserManagement.UserProviders;

namespace GrayMint.Authorization;

internal interface IAuthorizationImporter
{
    public UserProvider UserProvider { get; set; }
    public RoleProvider RoleProvider { get; set; }
    public TeamControllerBase TeamController { get; set; }
    public GrayMintAuthentication GrayMintAuthentication { get; set; }
    public AuthenticationController AuthenticationControllerOptions { get; set; }
    public NestedResourceProvider NestedResourceProvider { get; set; }
}