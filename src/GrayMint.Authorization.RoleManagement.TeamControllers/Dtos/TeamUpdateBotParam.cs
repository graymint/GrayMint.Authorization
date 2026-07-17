using GrayMint.Common.Utils;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamUpdateBotParam
{
    public Patch<string?>? Name { get; init; }
}