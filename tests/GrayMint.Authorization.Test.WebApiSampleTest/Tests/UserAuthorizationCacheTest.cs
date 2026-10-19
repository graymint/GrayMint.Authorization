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
    public async Task Clear_reaches_an_item_after_a_slow_read()
    {
        var clock = new TestClock();
        using var memoryCache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var userAuthorizationCache = new UserAuthorizationCache(memoryCache);
        var userId = Guid.NewGuid().ToString();

        // a read of two minutes saves the item two minutes after the token was first touched
        await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "item", entry => {
            clock.UtcNow += TimeSpan.FromMinutes(2);
            return CreateItem(entry, "stale");
        });

        // past the token's 61 minutes from that first touch, still inside the item's 60
        clock.UtcNow += TimeSpan.FromMinutes(59.5);
        userAuthorizationCache.ClearUserItems(userId);
        var item = await userAuthorizationCache.GetOrCreateUserItemAsync(userId, "item",
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

    [TestMethod]
    public void Item_added_by_its_entry_is_capped_too()
    {
        var clock = new TestClock();
        using var memoryCache = new MemoryCache(new MemoryCacheOptions { Clock = clock });
        var userAuthorizationCache = new UserAuthorizationCache(memoryCache);

        // as the token validator does: the entry's own expiration first, then it becomes the user's item
        using (var entry = memoryCache.CreateEntry("item")) {
            entry.SetAbsoluteExpiration(TimeSpan.FromHours(2));
            userAuthorizationCache.AddUserItem(Guid.NewGuid().ToString(), entry);
            entry.Value = "stale";
        }

        clock.UtcNow += AuthorizationConstants.CacheTimeout + TimeSpan.FromMinutes(1);
        Assert.IsFalse(memoryCache.TryGetValue("item", out _));
    }

    private static Task<string> CreateItem(ICacheEntry entry, string value)
    {
        entry.SetAbsoluteExpiration(AuthorizationConstants.CacheTimeout);
        return Task.FromResult(value);
    }
}
