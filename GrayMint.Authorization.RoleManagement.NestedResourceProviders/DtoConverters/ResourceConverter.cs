using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Dtos;
using GrayMint.Authorization.RoleManagement.NestedResourceProviders.Models;

namespace GrayMint.Authorization.RoleManagement.NestedResourceProviders.DtoConverters;

internal static class ResourceConverter
{
    public static Resource ToDto(this ResourceModel model)
    {
        return new Resource
        {
            ResourceId = model.ResourceId,
            ParentResourceId = model.ParentResourceId,
        };
    }

    public static ResourceModel ToModel(this Resource model)
    {
        return new ResourceModel
        {
            ResourceId = model.ResourceId,
            ParentResourceId = model.ParentResourceId,
        };
    }
}