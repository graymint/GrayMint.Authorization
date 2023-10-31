using System;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public class UserRole
{
    public required string ResourceId { get; init; }
    public required Guid UserId { get; init; }
    public required Role Role { get; init; }
}