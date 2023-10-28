namespace GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;

internal class UserModel
{
    public Guid UserId { get; set; } = default!;
    public bool IsDisabled { get; set; }
    public string Email { get; set; } = default!;
    public string? Name { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? ProfileUrl { get; set; }
    public string? Phone { get; set; }
    public DateTime CreatedTime { get; set; }
    public DateTime? AccessedTime { get; set; }
    public string? AuthCode { get; set; }
    public bool IsEmailVerified { get; set; }
    public bool IsPhoneVerified { get; set; }
    public bool IsBot { get; set; }
    public string? Description { get; set; }
    public string? ExData { get; set; }
}