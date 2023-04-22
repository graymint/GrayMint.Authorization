using GrayMint.Common.Utils;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public class UserUpdateRequest
{
    public Patch<string>? Email { get; set; }
    public Patch<string?>? FirstName { get; set; }
    public Patch<string?>? LastName { get; set; }
    public Patch<string?>? Description { get; set; }
    public Patch<string?>? ExData { get; set; }
}

