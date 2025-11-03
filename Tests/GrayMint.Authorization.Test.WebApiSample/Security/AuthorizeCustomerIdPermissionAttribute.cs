using GrayMint.Authorization.PermissionAuthorizations;

namespace GrayMint.Authorization.Test.WebApiSample.Security;

public class AuthorizeCustomerIdPermissionAttribute : AuthorizePermissionAttribute
{
    public AuthorizeCustomerIdPermissionAttribute(string permission)
        : base(permission)
    {
        ResourceRoute = "apps:{appId}:customers:{customerId}";
    }
}