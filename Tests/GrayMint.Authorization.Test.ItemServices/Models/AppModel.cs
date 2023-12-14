namespace GrayMint.Authorization.Test.ItemServices.Models;

public class AppModel
{
    public int AppId { get; set; }
    public required string AppName { get; set; }
    public string? AuthorizationCode { get; set; } // use for microservices only
}