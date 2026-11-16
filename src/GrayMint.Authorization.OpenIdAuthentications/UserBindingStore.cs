using GrayMint.Authorization.Abstractions;
using GrayMint.Authorization.OpenIdAuthentications.Models;
using GrayMint.Authorization.OpenIdAuthentications.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace GrayMint.Authorization.OpenIdAuthentications;

// Which user each account at a provider is tied to.
public sealed class UserBindingStore(
    OpenIdDbContext dbContext,
    UserAuthorizationCache userAuthorizationCache,
    IMemoryCache memoryCache,
    IOptions<OpenIdAuthenticationOptions> options)
{
    // The user an account is tied to, or null. Kept for a while once found, and dropped with everything else
    // that is kept of the user. An account of no one is asked for anew each time: its first sign-in works at
    // once, and made-up accounts can't grow the cache.
    public async Task<string?> FindUserId(string providerName, string subject, CancellationToken cancellationToken)
    {
        if (subject.Length > OpenIdDbContext.MaxSubjectLength)
            return null;

        // the provider's length in front, so no two pairs of names read alike
        var cacheKey = $"graymint:auth:openid:binding:{providerName.Length}:{providerName}:{subject}";
        return await memoryCache.GetOrCreateAsync(cacheKey, async entry => {
            entry.SetAbsoluteExpiration(options.Value.CacheTimeout);
            var userGuid = await dbContext.UserBindings
                .Where(x => x.Provider == providerName && x.Subject == subject)
                .Select(x => (Guid?)x.UserId)
                .SingleOrDefaultAsync(cancellationToken);

            var userId = userGuid?.ToString();
            if (userId != null)
                userAuthorizationCache.AddUserItem(userId, entry);
            else
                UserAuthorizationCache.RefuseEntry(entry);

            return userId;
        });
    }

    // Ties the account to the user. False when the account or the user is tied already, also by a sign-in that
    // came at the same moment: the database lets one of them in.
    public async Task<bool> TryAdd(string providerName, string subject, string userId,
        CancellationToken cancellationToken)
    {
        // not asked first: two that come together would both find nobody tied, and only the table's keys
        // can turn one of them away
        var userGuid = Guid.Parse(userId);
        var binding = new UserBindingModel {
            Provider = providerName,
            Subject = subject,
            UserId = userGuid,
            CreatedTime = DateTime.UtcNow
        };
        dbContext.UserBindings.Add(binding);
        try {
            await dbContext.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException) {
            // Turned away by a key of the table, if the other sign-in is there now. Each database says that
            // in its own way, so the table is asked instead; anything else is an error.
            dbContext.Entry(binding).State = EntityState.Detached;
            if (await IsTied(providerName, subject, userGuid, cancellationToken))
                return false;

            throw;
        }
    }

    // Takes away the tie of an account to a user that is gone. Only that very tie: the account's other
    // sign-in may have tied it anew in the same moment.
    public async Task Remove(string providerName, string subject, string userId, CancellationToken cancellationToken)
    {
        var userGuid = Guid.Parse(userId);
        await dbContext.UserBindings
            .Where(x => x.Provider == providerName && x.Subject == subject && x.UserId == userGuid)
            .ExecuteDeleteAsync(cancellationToken);

        // what is kept of the tie goes with it, or the account would be found tied for a while longer
        userAuthorizationCache.ClearUserItems(userId);
    }

    private Task<bool> IsTied(string providerName, string subject, Guid userGuid, CancellationToken cancellationToken)
    {
        return dbContext.UserBindings.AnyAsync(
            x => (x.Provider == providerName && x.Subject == subject) || x.UserId == userGuid, cancellationToken);
    }
}
