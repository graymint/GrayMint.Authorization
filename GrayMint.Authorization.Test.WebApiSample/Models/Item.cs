namespace GrayMint.Authorization.WebApiSample.Models;

public class Item
{
    public int ItemId { get; set; }
    public int AppId { get; set; }
    public string ItemName { get; set; } = default!;
}