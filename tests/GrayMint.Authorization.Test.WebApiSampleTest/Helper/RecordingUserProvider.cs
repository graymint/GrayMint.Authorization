using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.UserProviders;
using GrayMint.Common.Generics;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Helper;

// keeps each user it hands out, as a provider with its own cache would, so a test sees whether a caller changed one
public class RecordingUserProvider(UserProvider userProvider, HandedOutUsers handedOutUsers) : IUserProvider
{
    public async Task<User> Create(UserCreateRequest request)
    {
        var user = await userProvider.Create(request);
        return handedOutUsers.Add(user);
    }

    public async Task<User> Update(string userId, UserUpdateRequest request)
    {
        var user = await userProvider.Update(userId, request);
        return handedOutUsers.Add(user);
    }

    public async Task<User> Get(string userId)
    {
        var user = await userProvider.Get(userId);
        return handedOutUsers.Add(user);
    }

    public async Task<User?> FindById(string userId)
    {
        var user = await userProvider.FindById(userId);
        return user != null ? handedOutUsers.Add(user) : null;
    }

    public async Task<User?> FindByEmail(string email)
    {
        var user = await userProvider.FindByEmail(email);
        return user != null ? handedOutUsers.Add(user) : null;
    }

    public async Task<User> GetByEmail(string email)
    {
        var user = await userProvider.GetByEmail(email);
        return handedOutUsers.Add(user);
    }

    public Task Remove(string userId)
    {
        return userProvider.Remove(userId);
    }

    public Task ResetAuthorizationCode(string userId)
    {
        return userProvider.ResetAuthorizationCode(userId);
    }

    public async Task<ListResult<User>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<string>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        var users = await userProvider.GetUsers(search: search, firstName: firstName, lastName: lastName,
            userIds: userIds, isBot: isBot, recordIndex: recordIndex, recordCount: recordCount);

        foreach (var user in users.Items)
            handedOutUsers.Add(user);

        return users;
    }
}
