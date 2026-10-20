using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace GrayMint.Authorization.Abstractions;

public class UserAuthorizationCache(IMemoryCache memoryCache)
{
    private readonly Lock _lockObject = new();
    private static TimeSpan CacheTimeout => AuthorizationConstants.CacheTimeout;

    // a Guid id is keyed in its standard form, so every way of writing it (upper case, no hyphens)
    // shares the same entries and every clear reaches them
    private static string BuildUserCacheKey(string userId)
    {
        var normalizedUserId = Guid.TryParse(userId, out var guid) ? guid.ToString() : userId;
        return $"graymint:auth:userid:{normalizedUserId}";
    }

    // every item of a user expires with the user's token, so a clear drops them all at once; the token
    // slides with each new item and no item lives longer than CacheTimeout, so it outlives its items
    private CancellationTokenSource GetUserTokenSource(string userId)
    {
        // under the lock, so a user never has a second token that a clear would miss
        lock (_lockObject)
            return memoryCache.GetOrCreate(BuildUserCacheKey(userId), entry => {
                // a minute past CacheTimeout: an item's time starts when it is saved, just after the last touch
                entry.SetSlidingExpiration(CacheTimeout + TimeSpan.FromMinutes(1));
                entry.RegisterPostEvictionCallback((_, value, _, _) => (value as CancellationTokenSource)?.Cancel());
                return new CancellationTokenSource(); // never disposed: a reader may still hold it
            }) ?? throw new InvalidOperationException("Could not create the user's cache token.");
    }

    private void TieToUser(string userId, ICacheEntry entry)
    {
        entry.AddExpirationToken(new CancellationChangeToken(GetUserTokenSource(userId).Token));
    }

    // MemoryCache keeps the earlier of an absolute and a relative expiration, so this caps both
    private static void CapExpiration(ICacheEntry entry)
    {
        if (entry.AbsoluteExpirationRelativeToNow is null || entry.AbsoluteExpirationRelativeToNow > CacheTimeout)
            entry.AbsoluteExpirationRelativeToNow = CacheTimeout;
    }

    public async Task<TItem> GetOrCreateRequiredUserItemAsync<TItem>(string userId, string itemKey,
        Func<ICacheEntry, Task<TItem>> factory)
    {
        var res = await GetOrCreateUserItemAsync(userId, itemKey, factory)
                  ?? throw new KeyNotFoundException($"The required {itemKey} does not exist in UserAuthorizationCache");
        return res;
    }

    public async Task<TItem?> GetOrCreateUserItemAsync<TItem>(string userId, string itemKey,
        Func<ICacheEntry, Task<TItem>> factory)
    {
        var itemCacheKey = $"{BuildUserCacheKey(userId)}:{itemKey}";
        var res = await memoryCache.GetOrCreateAsync(itemCacheKey, async entry => {
            // tied before the read, so a clear during the read leaves nothing cached
            TieToUser(userId, entry);
            var item = await factory(entry);
            CapExpiration(entry);

            // touched again once read, so however long the read took, the token outlives the item
            _ = GetUserTokenSource(userId);
            return item;
        });

        return res;
    }

    // makes an entry being created one of the user's items, when its user is known only once read;
    // call it after setting the entry's expiration
    public void AddUserItem(string userId, ICacheEntry entry)
    {
        TieToUser(userId, entry);
        CapExpiration(entry);
    }

    public void ClearUserItems(string userId)
    {
        var userCacheKey = BuildUserCacheKey(userId);

        // cancelled before it can no longer be found, so a clear that finds no token finds no live item
        // either; CancelAsync sets the signal at once and runs the items' callbacks off the lock
        lock (_lockObject) {
            if (!memoryCache.TryGetValue(userCacheKey, out CancellationTokenSource? tokenSource))
                return;

            _ = tokenSource?.CancelAsync();
            memoryCache.Remove(userCacheKey);
        }
    }
}
