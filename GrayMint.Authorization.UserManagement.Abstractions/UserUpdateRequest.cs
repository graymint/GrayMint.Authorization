using GrayMint.Common.Utils;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public class UserUpdateRequest
{
    public Patch<string>? Email { get; set; }
    public Patch<string?>? Name { get; set; }
    public Patch<string?>? FirstName { get; set; }
    public Patch<string?>? LastName { get; set; }
    public Patch<string?>? Phone { get; set; }
    public Patch<bool>? IsDisabled { get; set; }
    public Patch<bool>? IsEmailVerified { get; set; }
    public Patch<bool>? IsPhoneVerified { get; set; }
    public Patch<string?>? PictureUrl { get; set; }
    public Patch<string?>? Description { get; set; }
    public Patch<string?>? ExData { get; set; }
}

