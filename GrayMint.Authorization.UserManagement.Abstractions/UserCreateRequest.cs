namespace GrayMint.Authorization.UserManagement.Abstractions;

public class UserCreateRequest
{
    public required string Email { get; init; }
    public string? Name { get; set; }
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? Phone { get; init; }
    public bool IsBot { get; init; }
    public bool IsDisabled { get; init; }
    public bool IsEmailVerified { get; init; }
    public bool IsPhoneVerified { get; init; }
    public string? PictureUrl { get; set; }
    public string? Description { get; init; }
    public string? ExData { get; init; }
}