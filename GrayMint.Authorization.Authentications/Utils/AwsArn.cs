using System.Text;

namespace GrayMint.Authorization.Authentications.Utils;

public class AwsArn
{
    public string Partition { get; set; }
    public string Service { get; set; }
    public string Region { get; set; }
    public string Account { get; set; }
    public string? ResourceType { get; set; }
    public string ResourceId { get; set; }

    public AwsArn(string arn)
    {
        arn = arn.Trim().Replace('/', ':');
        var items = arn.Split(':');
        Partition = items[1];
        Service = items[2];
        Region = items[3];
        Account = items[4];
        ResourceType = items.Length == 6 ? null : items[5];
        ResourceId = items.Length == 6 ? items[5] : items[6];
    }

    public override string ToString()
    {
        var stringBuilder = new StringBuilder();
        stringBuilder.Append("arn:");
        stringBuilder.Append(Partition);
        stringBuilder.Append(":");
        stringBuilder.Append(Service);
        stringBuilder.Append(":");
        stringBuilder.Append(Region);
        stringBuilder.Append(":");
        stringBuilder.Append(Account);
        stringBuilder.Append(":");
        stringBuilder.Append(ResourceId);
        return stringBuilder.ToString();
    }
}