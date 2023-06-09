﻿using GrayMint.Authorization.RoleManagement.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class UserRole : IUserRole
{
    private readonly IUserRole _userRole;
    
    public UserRole(IUserRole userRole, IUser? user)
    {
        _userRole = userRole;
        User = user != null ? new User(user) : null;
        Role = new Role(userRole.Role);
    }


    public User? User { get; }
    public string ResourceId => _userRole.ResourceId;
    public Guid UserId => _userRole.UserId;
    public Role Role { get; } // returning an interface will cause problem for nswag client generator
    IRole IUserRole.Role => _userRole.Role;

}