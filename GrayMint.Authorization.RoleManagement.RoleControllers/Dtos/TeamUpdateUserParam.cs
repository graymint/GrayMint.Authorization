using GrayMint.Common.Utils;

namespace GrayMint.Authorization.RoleManagement.RoleControllers.Dtos;

public class TeamUpdateUserParam
{
    public Patch<Guid>? RoleId { get; set; }
}