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
    public bool IsDisabled => _user.IsDisabled;
    public string Email => _user.Email;
    public string? Name => _user.Name;
    public string? FirstName => _user.FirstName;
    public string? LastName => _user.LastName;
    public string? ProfileUrl => _user.ProfileUrl;
    public string? Phone => _user.Phone;
    public string? Description => _user.Description;
    public DateTime CreatedTime => _user.CreatedTime;
    public DateTime? AccessedTime => _user.AccessedTime;
    public string? AuthorizationCode => _user.AuthorizationCode;
    public bool IsEmailVerified => _user.IsEmailVerified;
    public bool IsPhoneVerified => _user.IsPhoneVerified; 
    public bool IsBot => _user.IsBot;
    public string? ExData => _user.ExData;
}