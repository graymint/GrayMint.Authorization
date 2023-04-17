using System;
using System.Collections.Generic;
using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.Abstractions;

public static class AuthorizationCache
{
    public static void AddKey(IMemoryCache memoryCache, Guid userId, string key)
    {
        CreateKey(memoryCache, userId, key);
    }

    public static string CreateKey(IMemoryCache memoryCache, Guid userId, string key)
    {
        return CreateKeyInternal(memoryCache, $"graymint:auth:userid:{userId}", key);
    }

    public static void ResetUser(IMemoryCache memoryCache, Guid userId)
    {
        ResetUser(memoryCache, $"graymint:auth:userid:{userId}");
    }

    public static string CreateKeyInternal(IMemoryCache memoryCache, string userKey, string key)
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