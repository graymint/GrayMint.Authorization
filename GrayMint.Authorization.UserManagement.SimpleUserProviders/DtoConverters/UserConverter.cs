using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders.DtoConverters;

internal static class UserConverter
{
    public static User ToDto(this UserModel model)
    {
        var user = new User
        {
            UserId = model.UserId,
            Email = model.Email,
            IsDisabled = model.IsDisabled,
            CreatedTime = model.CreatedTime,
            AuthorizationCode = model.AuthCode,
            FirstName = model.FirstName,
            LastName = model.LastName,
            AccessedTime = model.AccessedTime,
            Description = model.Description,
            IsEmailVerified = model.IsEmailVerified,
            IsPhoneVerified = model.IsPhoneVerified,
            Phone = model.Phone,
            Name = model.Name,
            ProfileUrl = model.ProfileUrl,
            IsBot = model.IsBot,
            ExData = model.ExData
        };

        return user;
    }
}