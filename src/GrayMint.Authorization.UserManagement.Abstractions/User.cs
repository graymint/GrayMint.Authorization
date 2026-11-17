namespace GrayMint.Authorization.UserManagement.Abstractions;

/// <summary>
/// A user: a person, or a bot that a script or another service calls the API with.
/// </summary>
public class User
{
    /// <summary>
    /// The user's id.
    /// </summary>
    public required string UserId { get; set; }
    /// <summary>
    /// The user's email; a bot's is made up.
    /// </summary>
    public required string? Email { get; set; }
    /// <summary>
    /// The full name, from the identity provider.
    /// </summary>
    public required string? Name { get; set; }
    /// <summary>
    /// The first name; a bot's name is here.
    /// </summary>
    public required string? FirstName { get; set; }
    /// <summary>
    /// The last name.
    /// </summary>
    public required string? LastName { get; set; }
    /// <summary>
    /// The address of the user's picture.
    /// </summary>
    public required string? PictureUrl { get; set; }
    /// <summary>
    /// The phone number.
    /// </summary>
    public required string? Phone { get; set; }
    /// <summary>
    /// When the account was made, in UTC.
    /// </summary>
    public required DateTime CreatedTime { get; set; }
    /// <summary>
    /// When the user last made a request, in UTC. Answers show it for bots only.
    /// </summary>
    public required DateTime? AccessedTime { get; set; }
    /// <summary>
    /// The code every token of the user carries, so changing it ends them all. Answers leave it empty.
    /// </summary>
    public required string? AuthorizationCode { get; set; }
    /// <summary>
    /// Whether the account is turned off.
    /// </summary>
    public required bool IsDisabled { get; set; }
    /// <summary>
    /// Whether the email is verified.
    /// </summary>
    public required bool IsEmailVerified { get; set; }
    /// <summary>
    /// Whether the phone number is verified.
    /// </summary>
    public required bool IsPhoneVerified { get; set; }
    /// <summary>
    /// Whether the user is a bot.
    /// </summary>
    public required bool IsBot { get; set; }
    /// <summary>
    /// The service's own note on the user. Answers leave it empty.
    /// </summary>
    public required string? Description { get; set; }
    /// <summary>
    /// The service's own data on the user. Answers leave it empty.
    /// </summary>
    public required string? ExData { get; set; }

    // a provider may hand out the very user it caches, so an answer that hides part of it changes a copy
    public User Clone()
    {
        return (User)MemberwiseClone();
    }
}