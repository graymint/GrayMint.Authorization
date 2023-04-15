namespace GrayMint.Authorization.RoleManagement.RoleControllers;

public class RoleControllerOptions
{
    public bool AllowUserSelfRegister { get; set; }
    public bool AllowUserApiKey { get; set; }
    public bool AllowBotAppOwner { get; set; }
    public bool AllowOwnerSelfRemove { get; set; }
    public bool IsTestEnvironment { get; set; }
}