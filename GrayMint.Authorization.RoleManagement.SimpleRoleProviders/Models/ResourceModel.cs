using System.Collections.Generic;

namespace GrayMint.Authorization.RoleManagement.SimpleRoleProviders.Models;

internal class ResourceModel
{
    public required string ResourceId { get; set; }
    public required string? ParentResourceId { get; set; }

    public virtual ResourceModel? ParentResource { get; set; }
    public virtual IEnumerable<UserRoleModel>? UserRoles { get; set; }
}   