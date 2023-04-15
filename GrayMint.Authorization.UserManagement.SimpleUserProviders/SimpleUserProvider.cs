using GrayMint.Authorization.UserManagement.Abstractions;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.DtoConverters;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Models;
using GrayMint.Authorization.UserManagement.SimpleUserProviders.Persistence;
using GrayMint.Common.Generics;
using Microsoft.EntityFrameworkCore;

namespace GrayMint.Authorization.UserManagement.SimpleUserProviders;

public class SimpleUserProvider : IUserProvider
{
    private readonly SimpleUserDbContext _simpleUserDbContext;

    public SimpleUserProvider(
        SimpleUserDbContext simpleUserDbContext)
    {
        _simpleUserDbContext = simpleUserDbContext;
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

        return res.Entity.ToDto();
    }


    public async Task Update(Guid userId, UserUpdateRequest request)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        if (request.FirstName != null) user.FirstName = request.FirstName;
        if (request.LastName != null) user.LastName = request.LastName;
        if (request.Description != null) user.Description = request.Description;
        if (request.Email != null) user.Email = request.Email;
        if (request.IsBot != null) user.IsBot = request.IsBot;
        if (request.ExData != null) user.ExData = request.ExData;
        await _simpleUserDbContext.SaveChangesAsync();
    }

    public async Task<IUser> Get(Guid userId)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        return user.ToDto();
    }

    public async Task<IUser?> FindByEmail(string email)
    {
        var user = await _simpleUserDbContext.Users.SingleOrDefaultAsync(x => x.Email == email);
        return user?.ToDto();
    }

    public async Task<IUser> GetByEmail(string email)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.Email == email);
        return user.ToDto();
    }

    public async Task Remove(Guid userId)
    {
        _simpleUserDbContext.ChangeTracker.Clear();

        var user = new UserModel { UserId = userId };
        _simpleUserDbContext.Users.Remove(user);
        await _simpleUserDbContext.SaveChangesAsync();
    }

    public async Task ResetAuthorizationCode(Guid userId)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        user.AuthCode = Guid.NewGuid().ToString();
        await _simpleUserDbContext.SaveChangesAsync();
    }

    public async Task<ListResult<IUser>> GetUsers(string? search = null, 
        IEnumerable<Guid>? userIds = null, bool? isBot = null, 
        int recordIndex = 0, int? recordCount = null)
    {
        recordCount ??= int.MaxValue;
        if (!Guid.TryParse(search, out var searchGuid)) searchGuid = Guid.Empty;

        await using var trans = await _simpleUserDbContext.WithNoLockTransaction();
        var query = _simpleUserDbContext.Users
            .Where(x =>
                (isBot == null || x.IsBot == isBot) &&
                (userIds == null || userIds.Contains(x.UserId)))
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

    public async Task UpdateAccessedTime(Guid userId)
    {
        var user = await _simpleUserDbContext.Users.SingleAsync(x => x.UserId == userId);
        user.AccessedTime = DateTime.Now;
        await _simpleUserDbContext.SaveChangesAsync();
    }
}
