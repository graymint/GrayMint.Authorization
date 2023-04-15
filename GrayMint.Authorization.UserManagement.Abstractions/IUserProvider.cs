using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.UserManagement.Abstractions;

public interface IUserProvider
{
    Task<IUser> Create(UserCreateRequest request);
    Task Update(Guid userId, UserUpdateRequest request);
    Task<IUser> Get(Guid userId);
    Task<IUser?> FindByEmail(string email);
    Task<IUser> GetByEmail(string email);
    Task Remove(Guid userId);
    Task ResetAuthorizationCode(Guid userId);
    Task<ListResult<IUser>> GetUsers(
        string? search = null, IEnumerable<Guid>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null);

}