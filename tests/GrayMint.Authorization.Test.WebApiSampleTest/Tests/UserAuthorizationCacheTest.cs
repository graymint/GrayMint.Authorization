using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.Test.WebApiSampleTest.Helper;
using Microsoft.Extensions.Caching.Memory;

namespace GrayMint.Authorization.Test.WebApiSampleTest.Tests;

[TestClass]
public class UserAuthorizationCacheTest
{
    [TestMethod]
    public async Task Clear_reaches_an_item_created_late_in_the_user_cache_life()
    {
        var clock = new TestClock();
        using var memoryCache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var userAuthorizationCache = new UserAuthorizationCache(memoryCache);
        var userId = Guid.NewGuid().ToString();

        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "early", entry => CreateItem(entry, "early"));
        clock.UtcNow += TimeSpan.FromMinutes(50);
        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "late", entry => CreateItem(entry, "stale"));

        // an hour after the first item, the late one still lives and a clear must reach it
        clock.UtcNow += TimeSpan.FromMinutes(11);
        userAuthorizationCache.ClearUserItems(userId);
        var item = await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "late",
            entry => CreateItem(entry, "fresh"));
        Assert.AreEqual("fresh", item);
    }

    [TestMethod]
    public async Task Clear_during_a_read_leaves_nothing_cached()
    {
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());
        var userAuthorizationCache = new UserAuthorizationCache(memoryCache);
        var userId = Guid.NewGuid().ToString();

        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "item", entry => {
            userAuthorizationCache.ClearUserItems(userId);
            return CreateItem(entry, "stale");
        });

        var item = await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "item",
            entry => CreateItem(entry, "fresh"));
        Assert.AreEqual("fresh", item);
    }

    [TestMethod]
    public async Task No_item_outlives_the_cache_timeout()
    {
        var clock = new TestClock();
        using var memoryCache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var userAuthorizationCache = new UserAuthorizationCache(memoryCache);
        var userId = Guid.NewGuid().ToString();

        // items asking for two hours, by a relative and by an absolute expiration
        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "relative", entry => {
            entry.SetAbsoluteExpiration(TimeSpan.FromHours(2));
            return Task.FromResult("stale");
        });
        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "absolute", entry => {
            entry.SetAbsoluteExpiration(clock.UtcNow.AddHours(2));
            return Task.FromResult("stale");
        });

        clock.UtcNow += AuthorizationConstants.CacheTimeout + TimeSpan.FromMinutes(1);
        foreach (var itemKey in new[] { "relative", "absolute" }) {
            var item = await userAuthorizationCache.GetOrCreateUserItemAsync(userId, itemKey,
                entry => CreateItem(entry, "fresh"));
            Assert.AreEqual("fresh", item);
        }
    }

    private static Task<string> CreateItem(ICacheEntry entry, string value)
    {
        entry.SetAbsoluteExpiration(AuthorizationConstants.CacheTimeout);
        return Task.FromResult(value);
    }
}
