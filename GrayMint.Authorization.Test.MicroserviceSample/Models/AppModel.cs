namespace GrayMint.Authorization.Test.MicroserviceSample.Models;

public class AppModel
{
    public int AppId { get; set; }
    public required string AppName { get; set; }
    public string? AuthorizationCode { get; set; }
}