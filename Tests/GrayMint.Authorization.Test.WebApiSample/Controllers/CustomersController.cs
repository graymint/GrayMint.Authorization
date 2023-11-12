using GrayMint.Authorization.Test.WebApiSample.Security;
using Microsoft.AspNetCore.Mvc;

namespace GrayMint.Authorization.Test.WebApiSample.Controllers;

// ReSharper disable once RouteTemplates.RouteParameterConstraintNotResolved
[ApiController]
[Route("/api/v{version:apiVersion}/apps/{appId}/customers")]
public class CustomersController : ControllerBase
{

    [HttpGet("{customerId:int}")]
    [AuthorizeCustomerIdPermission(Permissions.CustomerRead)]
    public Task<string> GetByCustomerId(int appId, int customerId)
    {
        return Task.FromResult($"{appId}:{customerId}");
    }
}