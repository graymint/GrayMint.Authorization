using System.Threading.Tasks;
using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.RoleManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

internal class SimpleRoleResourceProvider : IRoleResourceProvider
{
    public Task<string?> GetParentResourceId(string resourceId)
    {
        var res = resourceId == AuthorizationConstants.RootResourceId ?
            null :
            AuthorizationConstants.RootResourceId;
        
        return Task.FromResult(res);
    }
}