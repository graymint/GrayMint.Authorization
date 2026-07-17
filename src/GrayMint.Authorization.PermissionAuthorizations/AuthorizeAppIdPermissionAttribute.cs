namespace GrayMint.Authorization.PermissionAuthorizations;

public class AuthorizeAppIdPermissionAttribute : AuthorizePermissionAttribute
{
    public AuthorizeAppIdPermissionAttribute(string permission) : base(permission)
    {
        ResourceRoute = "{appId}";
    }
}