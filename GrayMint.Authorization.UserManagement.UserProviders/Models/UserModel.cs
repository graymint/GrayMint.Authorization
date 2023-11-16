namespace GrayMint.Authorization.UserManagement.UserProviders.Models;

internal class UserModel
{
    public required Guid UserId { get; set; }
    public bool IsDisabled { get; set; }
    public string? Email { get; set; }
    public string? Name { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? PictureUrl { get; set; }
    public string? Phone { get; set; }
    public DateTime CreatedTime { get; set; }
    public DateTime? AccessedTime { get; set; }
    public bool IsEmailVerified { get; set; }
    public bool IsPhoneVerified { get; set; }
    public bool IsBot { get; set; }
    public required string AuthCode { get; set; } 
    public string? Description { get; set; }
    public string? ExData { get; set; }
}