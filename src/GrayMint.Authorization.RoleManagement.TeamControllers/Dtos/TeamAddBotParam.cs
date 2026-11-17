namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

/// <summary>
/// A new bot.
/// </summary>
public class TeamAddBotParam
{
    /// <summary>
    /// The bot's name.
    /// </summary>
    public required string Name { get; init; }
}