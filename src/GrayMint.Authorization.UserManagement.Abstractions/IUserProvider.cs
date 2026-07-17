using GrayMint.Common.Generics;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public interface IUserProvider
{
    Task<User> Create(UserCreateRequest request);
    Task<User> Update(string userId, UserUpdateRequest request);
    Task<User> Get(string userId);
    Task<User?> FindById(string userId);
    Task<User?> FindByEmail(string email);
    Task<User> GetByEmail(string email);
    Task Remove(string userId);
    Task ResetAuthorizationCode(string userId);

    Task<ListResult<User>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<string>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null);
}