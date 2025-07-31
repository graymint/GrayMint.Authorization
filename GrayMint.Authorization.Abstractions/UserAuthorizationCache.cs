using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.Abstractions;

public class UserAuthorizationCache(IMemoryCache memoryCache)
{
    private readonly Lock _lockObject = new();
    private static TimeSpan CacheTimeout => AuthorizationConstants.CacheTimeout;

    private static string BuildUserCacheKey(string userId)
    {
        return $"graymint:auth:userid:{userId}";
    }

    public async Task<TItem> GetOrCreateRequiredUserItemAsync<TItem>(string userId, string itemKey, Func<ICacheEntry, Task<TItem>> factory)
    {
        var res = await GetOrCreateUserItemAsync(userId, itemKey, factory)
                  ?? throw new KeyNotFoundException($"The required {itemKey} does not exist in UserAuthorizationCache");
        return res;
    }

    public async Task<TItem?> GetOrCreateUserItemAsync<TItem>(string userId, string itemKey, Func<ICacheEntry, Task<TItem>> factory)
    {
        // get list of current users keys
        var userCacheKey = BuildUserCacheKey(userId);
        var keys = memoryCache.GetOrCreate(userCacheKey, entry =>
            {
                entry.SetAbsoluteExpiration(CacheTimeout);
                return new HashSet<string>();
            }
        );

        // Create a unique key for the user item in the mem cache
        var itemCacheKey = $"{userCacheKey}:{itemKey}";

        // add the itemCacheKey to user keys
        lock (_lockObject)
            keys?.Add(itemCacheKey);

        // add the key
        var res = await memoryCache.GetOrCreateAsync(itemCacheKey, factory);
        return res;
    }

    public void AddUserItem(string userId, string itemKey)
    {
        var keys = memoryCache.GetOrCreate(BuildUserCacheKey(userId), entry =>
            {
                entry.SetAbsoluteExpiration(CacheTimeout);
                return new HashSet<string>();
            }
        );

        lock (_lockObject)
            keys?.Add(itemKey);
    }

    public void ClearUserItems(string userId)
    {
        var userCacheKey = BuildUserCacheKey(userId);
        var keys = memoryCache.Get<HashSet<string>>(userCacheKey);
        if (keys == null) 
            return;

        foreach (var key in keys)
            if (keys.TryGetValue(key, out var actualKey))
                memoryCache.Remove(actualKey);

        // remove key itself
        memoryCache.Remove(userCacheKey);
    }
}