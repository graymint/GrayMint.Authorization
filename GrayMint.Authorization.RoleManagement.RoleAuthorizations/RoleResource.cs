namespace GrayMint.Authorization.RoleManagement.RoleAuthorizations;

public class RoleResource
{
    public string Resource { get; }

    public RoleResource(string? resource)
    {
        Resource = resource ?? "*";
    }
}