using System;
using System.Collections.Generic;
using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.Abstractions;

public static class AuthorizationCache
{
    private static string BuildUserIdCacheKey(Guid userId)
    {
        return $"graymint:auth:userid:{userId}";
    }

    public static string CreateKey(IMemoryCache memoryCache, Guid userId, string key)
    {
        return CreateKeyInternal(memoryCache, BuildUserIdCacheKey(userId), key);
    }

    public static void ResetUser(IMemoryCache memoryCache, Guid userId)
    {
        ResetUser(memoryCache, BuildUserIdCacheKey(userId));
    }

    public static void AddKey(IMemoryCache memoryCache, Guid userId, string key)
    {
        var keys = memoryCache.GetOrCreate(BuildUserIdCacheKey(userId), entry =>
            {
                entry.SetAbsoluteExpiration(TimeSpan.FromMinutes(60));
                return new HashSet<string>();
            }
        );

        keys?.Add(key);
    }

    private static string CreateKeyInternal(IMemoryCache memoryCache, string userKey, string key)
    {
        var keys = memoryCache.GetOrCreate(userKey, entry =>
            {
                entry.SetAbsoluteExpiration(TimeSpan.FromMinutes(60));
                return new HashSet<string>();
            }
        );

        var ret = $"{userKey}:{key}";
        keys?.Add(ret);
        return ret;
    }

    private static void ResetUser(IMemoryCache memoryCache, string userKey)
    {
        var keys = memoryCache.Get<HashSet<string>>(userKey);
        if (keys == null) return;

        foreach (var key in keys)
            if (keys.TryGetValue(key, out var actualKey))
                memoryCache.Remove(actualKey);
    }
}