using System.Collections.Concurrent;
using System.Text.Json;
using GrayMint.Authorization.UserManagement.Abstractions;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Helper;

// the users a provider handed out, each with how it looked then
public class HandedOutUsers
{
    private readonly ConcurrentDictionary<User, string> _users = new(ReferenceEqualityComparer.Instance);

    public User Add(User user)
    {
        _users.TryAdd(user, JsonSerializer.Serialize(user));
        return user;
    }

    public IReadOnlyList<User> GetAll()
    {
        return _users.Keys.ToArray();
    }

    public IReadOnlyList<User> GetChanged()
    {
        return _users
            .Where(x => JsonSerializer.Serialize(x.Key) != x.Value)
            .Select(x => x.Key)
            .ToArray();
    }
}
