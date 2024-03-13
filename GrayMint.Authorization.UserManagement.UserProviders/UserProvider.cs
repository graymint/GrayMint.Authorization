using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.UserProviders.DtoConverters;
using GrayMint.Authorization.UserManagement.UserProviders.Models;
using GrayMint.Authorization.UserManagement.UserProviders.Persistence;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.UserManagement.UserProviders;

public class UserProvider(
    UserDbContext userDbContext,
    UserAuthorizationCache userAuthorizationCache,
    IOptions<UserProviderOptions> userProviderOptions,
    IMemoryCache memoryCache)
    : IUserProvider
{
    public async Task<User> Create(UserCreateRequest request)
    {
        var res = await userDbContext.Users.AddAsync(new UserModel
        {
            UserId = Guid.NewGuid(), 
            Email = request.Email.Trim(),
            Name = request.Name?.Trim(),
            FirstName = request.FirstName?.Trim(),
            LastName = request.LastName?.Trim(),
            CreatedTime = DateTime.UtcNow,
            AccessedTime = null,
            Description = request.Description,
            AuthCode = Guid.NewGuid().ToString(),
            IsDisabled = request.IsDisabled,
            IsEmailVerified = request.IsEmailVerified,
            IsPhoneVerified = request.IsPhoneVerified,
            PictureUrl = request.PictureUrl,
            Phone = request.Phone?.Trim(),
            IsBot = request.IsBot,
            ExData = request.ExData
        });
        await userDbContext.SaveChangesAsync();

        memoryCache.Remove(GetCacheKeyForEmail(request.Email));
        return res.Entity.ToDto();
    }

    public async Task<User> Update(string userId, UserUpdateRequest request)
    {
        var user = await userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        if (request.Name != null) user.Name = request.Name?.Value?.Trim();
        if (request.FirstName != null) user.FirstName = request.FirstName?.Value?.Trim();
        if (request.LastName != null) user.LastName = request.LastName?.Value?.Trim();
        if (request.IsDisabled != null) user.IsDisabled = request.IsDisabled;
        if (request.IsPhoneVerified != null) user.IsPhoneVerified = request.IsPhoneVerified;
        if (request.IsEmailVerified != null) user.IsEmailVerified = request.IsEmailVerified;
        if (request.Phone != null) user.Phone = request.Phone?.Value?.Trim();
        if (request.PictureUrl != null) user.PictureUrl = request.PictureUrl?.Value?.Trim();
        if (request.Description != null) user.Description = request.Description;
        if (request.ExData != null) user.ExData = request.ExData;
        if (request.Email != null) user.Email = request.Email.Value.Trim();

        await userDbContext.SaveChangesAsync();
        userAuthorizationCache.ClearUserItems(userId);
        return user.ToDto();
    }

    public async Task<User?> FindById(string userId)
    {
        if (!Guid.TryParse(userId, out var uid))
            return null;

        var user = await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "provider:user-model",
            entry =>
            {
                entry.SetAbsoluteExpiration(userProviderOptions.Value.CacheTimeout);
                return userDbContext.Users.SingleOrDefaultAsync(x => x.UserId == uid);
            });

        return user?.ToDto();
    }

    public async Task<User> Get(string userId)
    {
        var user = await FindById(userId) ?? throw new NotExistsException("There is no user with the given id.");
        return user;
    }

    public async Task UpdateAccessedTime(string userId)
    {
        var user = await userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        user.AccessedTime = DateTime.UtcNow;
        await userDbContext.SaveChangesAsync();
    }

    public async Task Remove(string userId)
    {
        userDbContext.ChangeTracker.Clear();

        var user = userDbContext.Users.Single(x=>x.UserId == Guid.Parse(userId));
        userDbContext.Users.Remove(user);
        await userDbContext.SaveChangesAsync();
        userAuthorizationCache.ClearUserItems(userId);
    }

    public async Task ResetAuthorizationCode(string userId)
    {
        var user = await userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        user.AuthCode = Guid.NewGuid().ToString();
        await userDbContext.SaveChangesAsync();
        userAuthorizationCache.ClearUserItems(userId);
    }

    public async Task<User?> FindByEmail(string email)
    {
        email = email.Trim();
        var user = await userDbContext.Users.SingleOrDefaultAsync(x => x.Email == email);
        return user?.ToDto();
    }

    public async Task<User> GetByEmail(string email)
    {
        var user = await FindByEmail(email) ?? throw new NotExistsException("There is no user with the given email.");
        return user;
    }

    public async Task<ListResult<User>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<string>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        search = search?.Trim();
        recordCount ??= int.MaxValue;
        if (!Guid.TryParse(search, out var searchGuid)) searchGuid = Guid.Empty;

        await using var trans = await userDbContext.WithNoLockTransaction();
        var query = userDbContext.Users
            .Where(x =>
                (isBot == null || x.IsBot == isBot) &&
                (userIds == null || userIds.Contains(x.UserId.ToString())) &&
                (firstName == null || (x.FirstName != null && x.FirstName.StartsWith(firstName))) &&
                (lastName == null || (x.LastName != null && x.LastName.StartsWith(lastName))))
            .Where(x =>
                string.IsNullOrEmpty(search) ||
                (x.UserId == searchGuid && searchGuid != Guid.Empty) ||
                (x.FirstName != null && x.FirstName.StartsWith(search)) ||
                (x.LastName != null && x.LastName.StartsWith(search)) ||
                (x.Email != null && x.Email.StartsWith(search)));

        var results = await query
            .OrderBy(x => x.Email)
            .Skip(recordIndex)
            .Take(recordCount ?? int.MaxValue)
            .ToArrayAsync();

        var ret = new ListResult<User>
        {
            TotalCount = results.Length < recordCount ? recordIndex + results.Length : await query.LongCountAsync(),
            Items = results.Select(x => x.ToDto()).ToArray()
        };

        return ret;
    }

    private static string GetCacheKeyForEmail(string email)
    {
        return $"graymint:auth:user-provider:user-model:email={email}";
    }

}
