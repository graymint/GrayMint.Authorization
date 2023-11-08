using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Dtos;
using GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.DtoConverters;

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