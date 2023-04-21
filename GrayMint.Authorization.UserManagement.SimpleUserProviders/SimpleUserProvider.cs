using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.DtoConverters;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Persistence;
using GrayMint.Common.Exceptions;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders;

public class SimpleUserProvider : IUserProvider
{
    private readonly SimpleUserDbContext _simpleUserDbContext;
    private readonly IMemoryCache _memoryCache;

    public SimpleUserProvider(
        SimpleUserDbContext simpleUserDbContext,
        IMemoryCache memoryCache)
    {
        _simpleUserDbContext = simpleUserDbContext;
        _memoryCache = memoryCache;
    }

    public async Task<IUser> Create(UserCreateRequest request)
    {
        var res = await _simpleUserDbContext.Users.AddAsync(new UserModel
        {
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            CreatedTime = DateTime.UtcNow,
            AccessedTime = null,
            Description = request.Description,
            AuthCode = Guid.NewGuid().ToString(),
            IsBot = request.IsBot,
            ExData = request.ExData
        });
        await _simpleUserDbContext.SaveChangesAsync();

        _memoryCache.Remove(GetCacheKeyForEmail(request.Email));
        return res.Entity.ToDto();
    }

    public async Task Update(Guid userId, UserUpdateRequest request)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        if (request.FirstName != null) user.FirstName = request.FirstName;
        if (request.LastName != null) user.LastName = request.LastName;
        if (request.Description != null) user.Description = request.Description;
        if (request.IsBot != null) user.IsBot = request.IsBot;
        if (request.ExData != null) user.ExData = request.ExData;
        if (request.Email != null)
        {
            _memoryCache.Remove(GetCacheKeyForEmail(user.Email));
            _memoryCache.Remove(GetCacheKeyForEmail(request.Email));
            user.Email = request.Email;
        }

        await _simpleUserDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
    }

    public async Task<IUser> Get(Guid userId)
    {
        var cacheKey = AuthorizationCache.CreateKey(_memoryCache, userId, "provider:user-model");
        var user = await _memoryCache.GetOrCreateAsync(cacheKey, entry =>
        {
            entry.SetAbsoluteExpiration(TimeSpan.FromMinutes(60));
            return _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        }) ?? throw new Exception("provider cache has been corrupted.");

        return user.ToDto();
    }

    public async Task UpdateAccessedTime(Guid userId)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        user.AccessedTime = DateTime.UtcNow;
        await _simpleUserDbContext.SaveChangesAsync();

        var cacheKey = AuthorizationCache.CreateKey(_memoryCache, userId, "provider:user-model");
        _memoryCache.Set(cacheKey, user, TimeSpan.FromMinutes(60));
    }

    public async Task Remove(Guid userId)
    {
        _simpleUserDbContext.ChangeTracker.Clear();

        var user = new UserModel { UserId = userId };
        _simpleUserDbContext.Users.Remove(user);
        await _simpleUserDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
    }

    public async Task ResetAuthorizationCode(Guid userId)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        user.AuthCode = Guid.NewGuid().ToString();
        await _simpleUserDbContext.SaveChangesAsync();
        AuthorizationCache.ResetUser(_memoryCache, userId);
    }

    public async Task<IUser?> FindByEmail(string email)
    {
        //get from cache
        var cacheKey = GetCacheKeyForEmail(email);
        if (_memoryCache.TryGetValue(cacheKey, out UserModel? user) && user != null)
            return user.ToDto();

        //add to cache
        user = await _simpleUserDbContext.Users.SingleOrDefaultAsync(x => x.Email == email);
        if (user != null)
        {
            _memoryCache.Set(cacheKey, user);
            AuthorizationCache.AddKey(_memoryCache, user.UserId, cacheKey);
        }

        return user?.ToDto();
    }

    public async Task<IUser> GetByEmail(string email)
    {
        var user = await FindByEmail(email) ?? throw new NotExistsException("There is not user with the given email.");
        return user;
    }

    public async Task<ListResult<IUser>> GetUsers(
        string? search = null, string? firstName = null, string? lastName = null,
        IEnumerable<Guid>? userIds = null, bool? isBot = null,
        int recordIndex = 0, int? recordCount = null)
    {
        recordCount ??= int.MaxValue;
        if (!Guid.TryParse(search, out var searchGuid)) searchGuid = Guid.Empty;

        await using var trans = await _simpleUserDbContext.WithNoLockTransaction();
        var query = _simpleUserDbContext.Users
            .Where(x =>
                (isBot == null || x.IsBot == isBot) &&
                (userIds == null || userIds.Contains(x.UserId)) &&
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

        var ret = new ListResult<IUser>
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
