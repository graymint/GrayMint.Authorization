using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;

namespace GrayMint.Authorization.Abstractions;

public class UserAuthorizationCache(IMemoryCache memoryCache)
{
    private static readonly CancellationChangeToken RefusedToken = new(new CancellationToken(canceled: true));
    private static readonly CancellationChangeToken UncachedUserToken = new(CancellationToken.None);
    private readonly Lock _lockObject = new();
    private static TimeSpan CacheTimeout => AuthorizationConstants.CacheTimeout;

    // the cache refuses an entry whose token has already changed: for an answer not worth keeping, such as one
    // about an id of no one, so made-up ids can't grow the cache
    public static void RefuseEntry(ICacheEntry entry)
    {
        entry.AddExpirationToken(RefusedToken);
    }

    // refused only if its read made the user's token, so an answer about a user the cache already holds, such
    // as the request's own, is kept; judged by the token the read is tied to, so a concurrent read can't make
    // an id of no one look held (the marker never changes, so a kept entry keeps it harmlessly)
    public static void RefuseEntryForUncachedUser(ICacheEntry entry)
    {
        entry.AddExpirationToken(UncachedUserToken);
    }

    private static bool IsRefused(ICacheEntry entry)
    {
        return entry.ExpirationTokens.Any(x => x.HasChanged);
    }

    // a Guid id is keyed in its standard form, so every way of writing it (upper case, no hyphens)
    // shares the same entries and every clear reaches them
    private static string BuildUserCacheKey(string userId)
    {
        var normalizedUserId = Guid.TryParse(userId, out var guid) ? guid.ToString() : userId;
        return $"graymint:auth:userid:{normalizedUserId}";
    }

    // every item of a user expires with the user's token, so a clear drops them all at once; the token
    // slides with each new item and no item lives longer than CacheTimeout, so it outlives its items
    private CancellationTokenSource GetUserTokenSource(string userId, out bool isNew)
    {
        // under the lock, so a user never has a second token that a clear would miss
        lock (_lockObject) {
            var isCreated = false;
            var tokenSource = memoryCache.GetOrCreate(BuildUserCacheKey(userId), entry => {
                isCreated = true;

                // a minute past CacheTimeout: an item's time starts when it is saved, just after the last touch
                entry.SetSlidingExpiration(CacheTimeout + TimeSpan.FromMinutes(1));
                entry.RegisterPostEvictionCallback((_, value, _, _) => (value as CancellationTokenSource)?.Cancel());
                return new CancellationTokenSource(); // never disposed: a reader may still hold it
            }) ?? throw new InvalidOperationException("Could not create the user's cache token.");

            isNew = isCreated;
            return tokenSource;
        }
    }

    // drops the user's token only while it is still the one given, as a clear or another call may have replaced
    // it; cancelled before it can no longer be found, as a clear does, which only expires early whatever else
    // had tied to it meanwhile
    private void RemoveUserTokenSource(string userId, CancellationTokenSource tokenSource)
    {
        var userCacheKey = BuildUserCacheKey(userId);
        lock (_lockObject) {
            if (!memoryCache.TryGetValue(userCacheKey, out CancellationTokenSource? current) || current != tokenSource)
                return;

            _ = tokenSource.CancelAsync();
            memoryCache.Remove(userCacheKey);
        }
    }

    // slides the user's token without making one: a token gone during a read was cancelled with its items, so
    // the item being saved is refused anyway, and a new one would be left with nothing tied to it
    private void TouchUserTokenSource(string userId)
    {
        _ = memoryCache.TryGetValue(BuildUserCacheKey(userId), out _);
    }

    private CancellationTokenSource TieToUser(string userId, ICacheEntry entry, out bool isNewToken)
    {
        var tokenSource = GetUserTokenSource(userId, out isNewToken);
        entry.AddExpirationToken(new CancellationChangeToken(tokenSource.Token));
        return tokenSource;
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
            var tokenSource = TieToUser(userId, entry, out var isNewToken);
            var item = await factory(entry);
            CapExpiration(entry);

            if (isNewToken && entry.ExpirationTokens.Contains(UncachedUserToken))
                RefuseEntry(entry);

            // a refused item leaves behind no token it alone made, so an id of no one leaves nothing at all
            if (IsRefused(entry)) {
                if (isNewToken)
                    RemoveUserTokenSource(userId, tokenSource);
                return item;
            }

            // touched again once read, so however long the read took, the token outlives the item
            TouchUserTokenSource(userId);
            return item;
        });

        return res;
    }

    // makes an entry being created one of the user's items, when its user is known only once read;
    // call it after setting the entry's expiration
    public void AddUserItem(string userId, ICacheEntry entry)
    {
        TieToUser(userId, entry, out _);
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
