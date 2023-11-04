using GrayMint.Authorization.Authentications;
using GrayMint.Authorization.UserManagement.SimpleUserProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.RoleManagement.TeamControllers;
using GrayMint.Authorization.Authentications.Controllers;

namespace GrayMint.Authorization;

internal interface IAuthorizationImporter
{
    public SimpleUserProviderOptions SimpleUserProviderOptions { get; set; }
    public SimpleRoleProviderOptions SimpleRoleProviderOptions { get; set; }
    public TeamControllerOptions TeamControllerOptions { get; set; }
    public GrayMintAuthenticationOptions GrayMintAuthenticationOptions { get; set; }
    public AuthenticationControllerOptions AuthenticationControllerOptions { get; set; }
}