namespace GrayMint.Authorization.PermissionAuthorizations;

public class PermissionResource
{
   public string ResourceId { get; }

    public PermissionResource(string resourceId)
    {
        ResourceId = resourceId;
    }
}