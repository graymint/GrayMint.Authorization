using GrayMint.Common.Utils;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

/// <summary>
/// A change to a bot.
/// </summary>
public class TeamUpdateBotParam
{
    /// <summary>
    /// The bot's new name.
    /// </summary>
    public Patch<string?>? Name { get; init; }
}