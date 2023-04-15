
using System;

namespace GrayMint.Authorization.RoleManagement.Abstractions;

public interface IRole
{
    public Guid RoleId { get; }
    public string RoleName { get; }
    public string? Description { get; }
}
