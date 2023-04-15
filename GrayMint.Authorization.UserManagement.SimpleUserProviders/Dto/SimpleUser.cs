using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders.Dto;

public class SimpleUser : IUser
{
    public required Guid UserId { get; set; }
    public required string Email { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedTime { get; set; }
    public DateTime? AccessedTime { get; set; }
    public string? AuthorizationCode { get; set; }
    public bool IsBot { get; set; }
    public string? ExData { get; set; }
}