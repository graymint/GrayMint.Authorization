using System.Threading.Tasks;
using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders;

public interface IResourceProvider : IRoleResourceProvider
{
    string RootResourceId { get; }
    Task<Resource> Add(Resource resource);
    Task<Resource> Update(Resource resource);
    Task<Resource> Get(string resourceId);
    Task Remove(string resourceId);
}