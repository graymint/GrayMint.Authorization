using System;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public interface IUser
{
    public Guid UserId { get; }
    public string Email { get; }
    public string? FirstName { get; }
    public string? LastName { get; }
    public string? Description { get; }
    public DateTime CreatedTime { get; }
    public DateTime? AccessedTime { get; }
    public string? AuthorizationCode { get; }
    public bool IsBot { get; }
    public string? ExData { get; }
}
