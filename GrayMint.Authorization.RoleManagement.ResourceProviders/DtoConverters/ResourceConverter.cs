using GrayMint.Authorization.RoleManagement.ResourceProviders.Dtos;
using GrayMint.Authorization.RoleManagement.ResourceProviders.Models;

namespace GrayMint.Authorization.RoleManagement.ResourceProviders.DtoConverters;

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