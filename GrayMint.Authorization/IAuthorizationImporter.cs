using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.UserManagement.SimpleUserProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.Authentications.Controllers.Controllers;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders;
using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

namespace GrayMint.Authorization;

internal interface IAuthorizationImporter
{
    public SimpleUserProvider SimpleUserProvider { get; set; }
    public SimpleRoleProvider SimpleRoleProvider { get; set; }
    public TeamControllerBase TeamController { get; set; }
    public GrayMintAuthentication GrayMintAuthentication { get; set; }
    public AuthenticationController AuthenticationControllerOptions { get; set; }
    public NestedResourceProvider NestedResourceProvider { get; set; }
}