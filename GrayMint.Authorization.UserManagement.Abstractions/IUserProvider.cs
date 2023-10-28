using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public interface IUserProvider
{
    Task<User> Create(UserCreateRequest request);
    Task<User> Update(Guid userId, UserUpdateRequest request);
    Task<User> Get(Guid userId);
    Task<User?> FindById(Guid userId);
    Task<User?> FindByEmail(string email);
    Task<User> GetByEmail(string email);
    Task Remove(Guid userId);
    Task ResetAuthorizationCode(Guid userId);
    Task<ListResult<User>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<Guid>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null);

}