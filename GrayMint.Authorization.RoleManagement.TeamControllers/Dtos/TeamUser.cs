using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.RoleManagement.TeamControllers.Dtos;

public class TeamUser : IUser
{
    private readonly IUser _user;

    public TeamUser(IUser user)
    {
        _user = user;
    }

    public Guid UserId => _user.UserId;

    public string Email => _user.Email;

    public string? FirstName => _user.FirstName;

    public string? LastName => _user.LastName;

    public string? Description => _user.Description;

    public DateTime CreatedTime => _user.CreatedTime;

    public DateTime? AccessedTime => _user.AccessedTime;

    public string? AuthorizationCode => _user.AuthorizationCode;

    public bool IsBot => _user.IsBot;

    public string? ExData => _user.ExData;
}