using System;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IUserRole
{
    public string ResourceId { get; }
    public Guid UserId { get; }
    public IRole Role { get; }
}