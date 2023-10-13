namespace GrayMint.Authorization.RoleManagement.TeamControllers;

public class TeamControllerOptions
{
    public bool AllowUserSelfRegister { get; set; }
    public bool AllowUserApiKey { get; set; }
    public bool AllowBotAppOwner { get; set; }
    public bool AllowOwnerSelfRemove { get; set; }
    public bool AllowUserMultiRole { get; set; }
    public bool IsTestEnvironment { get; set; }
    public TimeSpan UserTokenShortExpiration { get; set; } = TimeSpan.FromDays(3);
    public TimeSpan UserTokenLongExpiration { get; set; } = TimeSpan.FromDays(30);

}