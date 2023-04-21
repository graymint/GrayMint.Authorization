using GrayMint.Authorization.UserManagement.SimpleUserProviders;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders;
using GrayMint.Authorization.RoleManagement.RoleAuthorizations;
using GrayMint.Authorization.RoleManagement.TeamControllers.Controllers;

namespace GrayMint.Authorization;

internal interface IAuthorizationImporter
{
    public SimpleUserProvider SimpleUserProvider { get; set; }
    public SimpleRoleProvider SimpleRoleProvider { get; set; }
    public RoleAuthorizationService RoleAuthorizationService { get; set; }
    public TeamControllerBase TeamControllerBase { get; set; }
}