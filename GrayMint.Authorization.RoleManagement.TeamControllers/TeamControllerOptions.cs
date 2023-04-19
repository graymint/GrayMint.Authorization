namespace GrayMint.Authorization.RoleManagement.TeamControllers;

public class TeamControllerOptions
{
    public bool AllowUserSelfRegister { get; set; }
    public bool AllowUserApiKey { get; set; }
    public bool AllowBotAppOwner { get; set; }
    public bool AllowOwnerSelfRemove { get; set; }
    public bool AllowUserMultirole { get; set; }
    public bool IsTestEnvironment { get; set; }
}