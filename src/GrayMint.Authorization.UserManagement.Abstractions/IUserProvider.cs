using GrayMint.Common.Generics;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public interface IUserProvider
{
    Task<User> Create(UserCreateRequest request, CancellationToken cancellationToken);
    Task<User> Update(string userId, UserUpdateRequest request, CancellationToken cancellationToken);
    Task<User> Get(string userId, CancellationToken cancellationToken);
    Task<User?> FindById(string userId, CancellationToken cancellationToken);
    Task<User?> FindByEmail(string email, CancellationToken cancellationToken);
    Task<User> GetByEmail(string email, CancellationToken cancellationToken);
    Task Remove(string userId, CancellationToken cancellationToken);
    Task ResetAuthorizationCode(string userId, CancellationToken cancellationToken);

    Task<ListResult<User>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<string>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null, CancellationToken cancellationToken = default);
}