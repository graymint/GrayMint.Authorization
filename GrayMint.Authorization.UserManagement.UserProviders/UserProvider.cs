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

public class UserProvider : IUserProvider
{
    private readonly UserDbContext _userDbContext;
    private readonly UserProviderOptions _userProviderOptions;
    private readonly IMemoryCache _memoryCache;

    public UserProvider(
        UserDbContext userDbContext,
        IOptions<UserProviderOptions> userProviderOptions,
        IMemoryCache memoryCache)
    {
        _userDbContext = userDbContext;
        _userProviderOptions = userProviderOptions.Value;
        _memoryCache = memoryCache;
    }

    public async Task<User> Create(UserCreateRequest request)
    {
        var res = await _userDbContext.Users.AddAsync(new UserModel
        {
            Email = request.Email,
            Name = request.Name,
            FirstName = request.FirstName,
            LastName = request.LastName,
            CreatedTime = DateTime.UtcNow,
            AccessedTime = null,
            Description = request.Description,
            AuthCode = Guid.NewGuid().ToString(),
            IsDisabled = request.IsDisabled,
            IsEmailVerified = request.IsEmailVerified,
            IsPhoneVerified = request.IsPhoneVerified,
            PictureUrl = request.PictureUrl,
            Phone = request.Phone,
            IsBot = request.IsBot,
            ExData = request.ExData
        });
        await _userDbContext.SaveChangesAsync();

        _memoryCache.Remove(GetCacheKeyForEmail(request.Email));
        return res.Entity.ToDto();
    }

    public async Task<User> Update(string userId, UserUpdateRequest request)
    {
        var user = await _userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        if (request.Name != null) user.Name = request.Name;
        if (request.FirstName != null) user.FirstName = request.FirstName;
        if (request.LastName != null) user.LastName = request.LastName;
        if (request.IsDisabled != null) user.IsDisabled = request.IsDisabled;
        if (request.IsPhoneVerified != null) user.IsPhoneVerified = request.IsPhoneVerified;
        if (request.IsEmailVerified != null) user.IsEmailVerified = request.IsEmailVerified;
        if (request.Phone != null) user.Phone = request.Phone;
        if (request.PictureUrl != null) user.PictureUrl = request.PictureUrl;
        if (request.Description != null) user.Description = request.Description;
        if (request.ExData != null) user.ExData = request.ExData;
        if (request.Email != null)
        {
            _memoryCache.Remove(GetCacheKeyForEmail(user.Email));
            _memoryCache.Remove(GetCacheKeyForEmail(request.Email));
            user.Email = request.Email;
        }

        await _userDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
        return user.ToDto();
    }

    public async Task<User?> FindById(string userId)
    {
        if (!Guid.TryParse(userId, out var uid))
            return null;

        var cacheKey = AuthorizationCache.CreateKey(_memoryCache, userId, "provider:user-model");
        var user = await _memoryCache.GetOrCreateAsync(cacheKey, entry =>
        {
            entry.SetAbsoluteExpiration(_userProviderOptions.CacheTimeout);
            return _userDbContext.Users.SingleOrDefaultAsync(x => x.UserId == uid);
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
        var user = await _userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        user.AccessedTime = DateTime.UtcNow;
        await _userDbContext.SaveChangesAsync();

        var cacheKey = AuthorizationCache.CreateKey(_memoryCache, userId, "provider:user-model");
        _memoryCache.Set(cacheKey, user, TimeSpan.FromMinutes(60));
    }

    public async Task Remove(string userId)
    {
        _userDbContext.ChangeTracker.Clear();

        var user = new UserModel { UserId = Guid.Parse(userId) };
        _userDbContext.Users.Remove(user);
        await _userDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
    }

    public async Task ResetAuthorizationCode(string userId)
    {
        var user = await _userDbContext.Users.SingleAsync(x => x.UserId == Guid.Parse(userId));
        user.AuthCode = Guid.NewGuid().ToString();
        await _userDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
    }

    public async Task<User?> FindByEmail(string email)
    {
        //get from cache
        var cacheKey = GetCacheKeyForEmail(email);
        if (_memoryCache.TryGetValue(cacheKey, out UserModel? user) && user != null)
            return user.ToDto();

        //add to cache
        user = await _userDbContext.Users.SingleOrDefaultAsync(x => x.Email == email);
        if (user != null)
        {
            _memoryCache.Set(cacheKey, user);
            AuthorizationCache.AddKey(_memoryCache, user.UserId.ToString(), cacheKey);
        }

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
        recordCount ??= int.MaxValue;
        if (!Guid.TryParse(search, out var searchGuid)) searchGuid = Guid.Empty;

        await using var trans = await _userDbContext.WithNoLockTransaction();
        var query = _userDbContext.Users
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
                (x.Email.StartsWith(search)));

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
