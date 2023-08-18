using GrayMint.Authorization.UserManagement.SimpleUserProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.Authentications.BotAuthentication;
using GrayMint.Authorization.Authentications.CognitoAuthentication;
using GrayMint.Authorization.RoleManagement.TeamControllers;

namespace GrayMint.Authorization;

internal interface IAuthorizationImporter
{
    public SimpleUserProviderOptions SimpleUserProviderOptions { get; set; }
    public SimpleRoleProviderOptions SimpleRoleProviderOptions { get; set; }
    public TeamControllerOptions TeamControllerOptions { get; set; }
    public BotAuthenticationOptions BotAuthenticationOptions { get; set; }
    public CognitoAuthenticationOptions CognitoAuthenticationOptions { get; set; }
}