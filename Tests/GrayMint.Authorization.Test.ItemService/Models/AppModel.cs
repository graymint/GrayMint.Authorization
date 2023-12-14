namespace GrayMint.Authorization.Test.ItemService.Models;

public class AppModel
{
    public int AppId { get; set; }
    public required string AppName { get; set; }
    public string? AuthorizationCode { get; set; } // use for microservices only
}