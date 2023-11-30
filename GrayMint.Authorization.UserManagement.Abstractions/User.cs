namespace GrayMint.Authorization.UserManagement.Abstractions;

public class User
{
    public required string UserId { get; set; }
    public required string? Email { get; set; }
    public required string? Name { get; set; }
    public required string? FirstName { get; set; }
    public required string? LastName { get; set; }
    public required string? PictureUrl { get; set; }
    public required string? Phone { get; set; }
    public required DateTime CreatedTime { get; set; }
    public required DateTime? AccessedTime { get; set; }
    public required string? AuthorizationCode { get; set; }
    public required bool IsDisabled { get; set; }
    public required bool IsEmailVerified { get; set; }
    public required bool IsPhoneVerified { get; set; }
    public required bool IsBot { get; set; }
    public required string? Description { get; set; }
    public required string? ExData { get; set; }
}
