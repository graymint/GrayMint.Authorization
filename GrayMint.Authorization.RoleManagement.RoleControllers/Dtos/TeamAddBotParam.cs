namespace GrayMint.Authorization.RoleManagement.RoleControllers.Dtos;

public class TeamAddBotParam
{
    public required string Name { get; init; }
    public required Guid RoleId { get; init; }
}