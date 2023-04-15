using GrayMint.Authorization.UserManagement.SimpleUserProviders.Dto;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders.DtoConverters;

internal static class UserConverter
{
    public static SimpleUser ToDto(this UserModel model)
    {
        var user = new SimpleUser
        {
            UserId = model.UserId,
            Email = model.Email,
            CreatedTime = model.CreatedTime,
            AuthorizationCode = model.AuthCode,
            FirstName = model.FirstName,
            LastName = model.LastName,
            AccessedTime = model.AccessedTime,
            Description = model.Description,
            IsBot = model.IsBot,
            ExData = model.ExData
        };

        return user;
    }
}