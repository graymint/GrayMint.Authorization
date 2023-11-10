
namespace GrayMint.Authorization.RoleManagement.ResourceProviders.Models;

internal class ResourceModel
{
    public required string ResourceId { get; set; }
    public required string? ParentResourceId { get; set; }
    public virtual ResourceModel? ParentResource { get; set; }
}   