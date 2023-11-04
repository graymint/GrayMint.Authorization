namespace GrayMint.Authorization.RoleManagement.TeamControllers;

public class TeamControllerOptions
{
    public bool AllowBotAppOwner { get; set; }
    public bool AllowOwnerSelfRemove { get; set; }
    public bool AllowUserMultiRole { get; set; }
    public bool IsTestEnvironment { get; set; }
}