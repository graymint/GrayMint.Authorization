namespace GrayMint.Authorization.Test.MicroserviceSample.Models;

public class ItemModel
{
    public int ItemId { get; set; }
    public required int AppId { get; set; }
    public required string ItemName { get; set; }
}