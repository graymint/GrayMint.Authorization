using GrayMint.Authorization.Test.WebApiSample.Security;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

[ApiController]
[Route("/api/apps/{appId:int}/customers")]
public class CustomersController : ControllerBase
{
    [HttpGet("{customerId:int}")]
    [AuthorizeCustomerIdPermission(Permissions.CustomerRead)]
    public Task<string> GetByCustomerId(int appId, int customerId)
    {
        return Task.FromResult($"{appId}:{customerId}");
    }
}